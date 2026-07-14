// Copyright © 2023 Axkea, spacewander
// Copyright © 2025 United Security Providers AG, Switzerland
// Copyright © 2025 Datum Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/anypb"

	"coraza-waf/internal/libinjection"
	"coraza-waf/internal/logging"
	"coraza-waf/internal/re2"
)

// MatchedRuleWithContext extends MatchedRule to optionally provide access to the
// transaction context, allowing extraction of the span context passed during
// transaction creation.
type MatchedRuleWithContext interface {
	ctypes.MatchedRule
	Context() context.Context
}

type Parser struct{}

type Configuration struct {
	Directives       WafDirectives
	DefaultDirective string
	HostDirectiveMap HostDirectiveMap
	WafMaps          WafMaps
	LogFormat        logging.LogFormat

	// WafInstanceRefs maps directive names to SHA-256 hashes of their directive strings,
	// used as cache keys for lazy WAF instantiation.
	WafInstanceRefs map[string]string

	// TraceRouteMetadataExtractorExpression is a CEL expression for extracting
	// trace attributes from Envoy route metadata.
	TraceRouteMetadataExtractorExpression string

	// EmitMatchedValue controls whether the matched value (which can carry
	// request payload) is emitted on rule-violation and interruption span
	// events. The matched variable name and key are always emitted; only the
	// value is gated. Defaults to false.
	EmitMatchedValue bool
}

type WafMaps map[string]coraza.WAF

type WafDirectives map[string]Directives

type Directives struct {
	SimpleDirectives []string `json:"simple_directives"`
}

type HostDirectiveMap map[string]string

// WafCache is the global WAF instance cache shared across all configurations.
var WafCache = NewWafCacheStore()

var filePathPrefix = regexp.MustCompile(".*/")
var maxMessageSize = 250
var logFormat = logging.FormatText
var emitMatchedValue = false

func (p Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (any, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}
	v := configStruct.Value
	var config Configuration
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	if useRe2, ok := v.AsMap()["use_re2"].(bool); !ok || useRe2 {
		re2.Register()
	}

	if useLibinjection, ok := v.AsMap()["use_libinjection"].(bool); !ok || useLibinjection {
		libinjection.Register()
	}

	if directivesString, ok := v.AsMap()["directives"].(string); ok {
		var wafDirectives WafDirectives
		err := json.UnmarshalFromString(directivesString, &wafDirectives)
		if err != nil {
			return nil, err
		}
		if len(wafDirectives) == 0 {
			return nil, errors.New("directives is empty")
		}
		config.Directives = wafDirectives

		// Compute SHA-256 hashes of directive strings for cache keys.
		// WAF instances are built lazily on first request via the cache.
		config.WafInstanceRefs = make(map[string]string, len(config.Directives))
		for wafName, wafRules := range config.Directives {
			directivesStr := strings.Join(wafRules.SimpleDirectives, "\n")
			directivesHash := sha256.Sum256([]byte(directivesStr))
			config.WafInstanceRefs[wafName] = fmt.Sprintf("%x", directivesHash)
		}

		// Also pre-build WAF maps for backward compatibility with non-cached code paths.
		wafMaps := make(WafMaps)
		for wafName, wafRules := range config.Directives {
			wafConfig := coraza.NewWAFConfig().WithErrorCallback(ErrorCallback).WithRootFS(Root).WithDirectives(strings.Join(wafRules.SimpleDirectives, "\n"))
			waf, err := coraza.NewWAF(wafConfig)
			if err != nil {
				return nil, fmt.Errorf("%s mapping waf init error:%s", wafName, err.Error())
			}
			wafMaps[wafName] = waf
		}
		config.WafMaps = wafMaps
	} else {
		return nil, errors.New("directives does not exist")
	}
	if defaultDirectiveString, ok := v.AsMap()["default_directive"].(string); ok {
		_, ok := config.Directives[defaultDirectiveString]
		if !ok {
			return nil, errors.New("the referenced default_directive does not exist in directives")
		}
		config.DefaultDirective = defaultDirectiveString
	} else {
		return nil, errors.New("default_directive does not exist")
	}

	// host_directives_map is not set, however we still need to initialize an empty host mapping
	if v.AsMap()["host_directive_map"] == nil {
		hostDirectiveMap := make(HostDirectiveMap)
		config.HostDirectiveMap = hostDirectiveMap

	} else {
		// try to read host_directives_map as JSON string
		if hostDirectiveMapString, ok := v.AsMap()["host_directive_map"].(string); ok {
			hostDirectiveMap := make(HostDirectiveMap)
			err := json.UnmarshalFromString(hostDirectiveMapString, &hostDirectiveMap)
			if err != nil {
				return nil, err
			}
			for host, rule := range hostDirectiveMap {
				_, ok := config.Directives[rule]
				if !ok {
					return nil, fmt.Errorf("the referenced directive '%s' for host %s does not exist", rule, host)
				}
			}
			config.HostDirectiveMap = hostDirectiveMap
		} else {
			return nil, errors.New("host_directive_map is not a JSON string")
		}
	}

	logging.Init(logging.FormatText)
	logger := logging.GetLogger()
	// read log format
	if logFormatString, ok := v.AsMap()["log_format"].(string); ok {
		if strings.ToLower(logFormatString) == "plain" {
			logFormatString = logging.FormatText.String()
			logger.Warn("DEPRECATION: 'plain' has been changed to 'text'")
		}

		switch format := logging.LogFormat(strings.ToLower(logFormatString)); format {
		case logging.FormatJson, logging.FormatText, logging.FormatFtw:
			config.LogFormat = format
		default:
			return nil, fmt.Errorf("invalid log_format. Only '%s' and '%s' is supported", logging.FormatJson, logging.FormatText)
		}
	} else {
		config.LogFormat = logging.FormatText
		logger.Info("No log_format provided. Using default 'text'")
	}

	logFormat = config.LogFormat

	// Parse trace_route_metadata_extractor if provided
	if extractorValue, ok := v.AsMap()["trace_route_metadata_extractor"]; ok {
		extractorExpr, ok := extractorValue.(string)
		if !ok {
			return nil, errors.New("trace_route_metadata_extractor must be a string")
		}
		config.TraceRouteMetadataExtractorExpression = strings.TrimSpace(extractorExpr)
	}

	if emitMatchedValueSetting, ok := v.AsMap()["emit_matched_value"].(bool); ok {
		config.EmitMatchedValue = emitMatchedValueSetting
	}
	emitMatchedValue = config.EmitMatchedValue

	return &config, nil
}

func (p Parser) Merge(parentConfig any, childConfig any) any {
	if parentConfig == nil {
		return childConfig
	}
	if childConfig == nil {
		return parentConfig
	}

	parent, ok := parentConfig.(*Configuration)
	if !ok {
		panic("unexpected parent config type")
	}
	child, ok := childConfig.(*Configuration)
	if !ok {
		panic("unexpected child config type")
	}

	if len(child.TraceRouteMetadataExtractorExpression) == 0 && len(parent.TraceRouteMetadataExtractorExpression) > 0 {
		child.TraceRouteMetadataExtractorExpression = parent.TraceRouteMetadataExtractorExpression
	}

	if !child.EmitMatchedValue && parent.EmitMatchedValue {
		child.EmitMatchedValue = parent.EmitMatchedValue
	}

	return child
}

// ErrorCallback is the coraza error callback that logs rule violations and
// records them as OTel trace events.
func ErrorCallback(error ctypes.MatchedRule) {
	// Try to extract the span context from the transaction if available
	ctx := context.Background()
	if ruleWithCtx, ok := error.(MatchedRuleWithContext); ok {
		if ruleCtx := ruleWithCtx.Context(); ruleCtx != nil {
			ctx = ruleCtx
		}
	}

	// Extract span from context and add rule violation event
	span := trace.SpanFromContext(ctx)
	if span != nil && span.IsRecording() {
		attrs := []attribute.KeyValue{
			attribute.Int("coraza.rule.id", error.Rule().ID()),
			attribute.String("coraza.rule.version", error.Rule().Version()),
			attribute.String("coraza.rule.message", error.Message()),
			attribute.String("coraza.rule.severity", error.Rule().Severity().String()),
			attribute.String("coraza.rule.file", error.Rule().File()),
			attribute.String("coraza.rule.uri", error.URI()),
		}
		if len(error.Rule().Tags()) > 0 {
			attrs = append(attrs, attribute.StringSlice("coraza.rule.tags", error.Rule().Tags()))
		}
		if mds := error.MatchedDatas(); len(mds) > 0 {
			md := mds[0]
			attrs = append(attrs,
				attribute.String("coraza.match.variable", md.Variable().Name()),
				attribute.String("coraza.match.key", md.Key()),
			)
			if emitMatchedValue {
				mv := md.Value()
				if len(mv) > maxMessageSize {
					mv = mv[:maxMessageSize]
				}
				attrs = append(attrs, attribute.String("coraza.match.value", mv))
			}
		}
		span.AddEvent("coraza.rule_violation", trace.WithAttributes(attrs...))
	}

	// FTW has its own log format because they expect the log to be formatted
	// in a specific way. Coraza already has a method that formats it correctly.
	if logFormat == logging.FormatFtw {
		msg := error.ErrorLog()
		switch error.Rule().Severity() {
		case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical:
			api.LogCritical(msg)
		case ctypes.RuleSeverityError:
			api.LogError(msg)
		case ctypes.RuleSeverityWarning:
			api.LogWarn(msg)
		case ctypes.RuleSeverityNotice, ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug:
			api.LogInfo(msg)
		}

		return
	}

	// the transaction ID was set to the request ID on transaction initalization, see filter.go
	// see https://github.com/corazawaf/coraza/discussions/1186
	xReqID := error.TransactionID()
	category := ""

	if err := uuid.Validate(xReqID); err != nil {
		// the request ID was not available and coraza has choosen a random ID
		xReqID = ""
	}
	// determine category from configuration file information
	cfi := filePathPrefix.ReplaceAllString(error.Rule().File(), "")
	cfi = strings.ReplaceAll(cfi, ".conf", "")
	if cfi != "" {
		category = cfi
	}
	matchData := error.MatchedDatas()[0]
	rule := error.Rule()
	msg := matchData.Message()
	for _, md := range error.MatchedDatas() {
		if md.Message() != "" {
			msg = md.Message()
			break
		}
	}
	msg = "WAF rule triggered: " + msg
	if len(msg) > maxMessageSize {
		msg = msg[:maxMessageSize]
	}
	value := matchData.Value()
	if len(value) > maxMessageSize {
		value = value[:maxMessageSize]
	}
	data := matchData.Data()
	if len(data) > maxMessageSize {
		data = data[:maxMessageSize]
	}

	logger := logging.GetLogger().With(
		"tx", error.TransactionID(),
		"hostname", error.ServerIPAddress(),
		"uri", error.URI(),
		"client", error.ClientIPAddress(),
		"request_id", xReqID,
	)
	logger = logger.WithGroup("crs").With(
		"version", rule.Version(),
	)
	logger = logger.WithGroup("violated_rule").With(
		"id", strconv.Itoa(rule.ID()),
		"revision", rule.Revision(),
		"version", rule.Version(),
		"file", rule.File(),
		"line", strconv.Itoa(rule.Line()),
		"message", error.Message(),
		"data", data,
		"severity", rule.Severity().String(),
		"maturity", strconv.Itoa(rule.Maturity()),
		"accuracy", strconv.Itoa(rule.Accuracy()),
		"category", category,
		"tags", rule.Tags(),
	)

	logger = logger.WithGroup("match").With(
		"name", matchData.Variable().Name(),
		"key", matchData.Key(),
		"op", rule.Operator(),
		"value", value,
	)

	switch error.Rule().Severity() {
	case ctypes.RuleSeverityEmergency, ctypes.RuleSeverityAlert, ctypes.RuleSeverityCritical, ctypes.RuleSeverityError:
		logger.Error(msg)
	case ctypes.RuleSeverityWarning:
		logger.Warn(msg)
	case ctypes.RuleSeverityNotice, ctypes.RuleSeverityInfo, ctypes.RuleSeverityDebug:
		logger.Info(msg)
	}
}

//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/anypb"
)

// MatchedRuleWithContext is an interface that extends MatchedRule
// to optionally provide access to the transaction context.
// This allows us to extract the span context passed during transaction creation.
type MatchedRuleWithContext interface {
	ctypes.MatchedRule
	Context() context.Context
}

func init() {
	_, err := setupOpenTelemetry(context.Background())

	if err != nil {
		panic(fmt.Sprintf("failed to setup OpenTelemetry: %v", err))
	}

	http.RegisterHttpFilterFactoryAndConfigParser("coraza-waf", configFactory(), &parser{})
}

type parser struct {
}

type configuration struct {
	directives       WafDirectives
	defaultDirective string
	hostDirectiveMap HostDirectiveMap
	logFormat        string

	// Simple cache for WAF instances so it's not recreated on every request
	wafInstances wafInstances
	wafMu        sync.RWMutex

	// A map of WAF directive names to their waf instance

	wafInstanceRefs             map[string]string
	traceRouteMetadataExtractor *metadataExtractorHandle
}

// func (c *configuration) Destroy() {

// }

var wafCache = newWafCacheStore()

type wafInstances map[string]coraza.WAF

type WafDirectives map[string]Directives

type Directives struct {
	SimpleDirectives []string `json:"simple_directives"`
}

type HostDirectiveMap map[string]string

type JSONRuleLogEntry struct {
	RuleID          int      `json:"id"`
	Category        string   `json:"category"`
	Severity        string   `json:"severity"`
	Data            string   `json:"data"`
	Message         string   `json:"message"`
	MatchedData     string   `json:"matched_data"`
	MatchedDataName string   `json:"matched_data_name"`
	Tags            []string `json:"tags"`
}

type JSONErrorLogLine struct {
	Url            string           `json:"request.path"`
	Rule           JSONRuleLogEntry `json:"crs.violated_rule"`
	ClientIP       string           `json:"client.address"`
	TransactionID  string           `json:"transaction.id"`
	RuleSetVersion string           `json:"crs.version"`
	RequestID      string           `json:"request.id"`
}

var filePathPrefix = regexp.MustCompile(".*/")
var logFormat string

func (p parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	api.LogCriticalf("Parsing coraza-waf config: %+v", any)
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}
	v := configStruct.Value
	var config configuration
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if directivesString, ok := v.AsMap()["directives"].(string); ok {
		var wafDirectives WafDirectives
		err := json.UnmarshalFromString(directivesString, &wafDirectives)
		if err != nil {
			return nil, err
		}
		if len(wafDirectives) == 0 {
			return nil, errors.New("directives is empty")
		}
		config.directives = wafDirectives
	} else {
		return nil, errors.New("directives does not exist")
	}
	if defaultDirectiveString, ok := v.AsMap()["default_directive"].(string); ok {
		_, ok := config.directives[defaultDirectiveString]
		if !ok {
			return nil, errors.New("the referenced default_directive does not exist in directives")
		}
		config.defaultDirective = defaultDirectiveString
	} else {
		return nil, errors.New("default_directive does not exist")
	}

	// host_directives_map is not set, however we still need to initialize an empty host mapping
	if v.AsMap()["host_directive_map"] == nil {
		hostDirectiveMap := make(HostDirectiveMap)
		config.hostDirectiveMap = hostDirectiveMap

	} else {
		// try to read host_directives_map as JSON string
		if hostDirectiveMapString, ok := v.AsMap()["host_directive_map"].(string); ok {
			hostDirectiveMap := make(HostDirectiveMap)
			err := json.UnmarshalFromString(hostDirectiveMapString, &hostDirectiveMap)
			if err != nil {
				return nil, err
			}
			for host, rule := range hostDirectiveMap {
				_, ok := config.directives[rule]
				if !ok {
					return nil, fmt.Errorf("the referenced directive '%s' for host %s does not exist", rule, host)
				}
			}
			config.hostDirectiveMap = hostDirectiveMap
		} else {
			return nil, errors.New("host_directive_map is not a JSON string")
		}
	}

	// read log format
	if logFormatString, ok := v.AsMap()["log_format"].(string); ok {
		if strings.ToLower(logFormatString) == "json" || strings.ToLower(logFormatString) == "plain" {
			config.logFormat = strings.ToLower(logFormatString)
			logFormat = strings.ToLower(logFormatString)
		} else {
			return nil, errors.New("Invalid log_format. Only 'json' and 'plain' is supported")
		}
	} else {
		config.logFormat = "plain"
		logFormat = "plain"
		api.LogInfo(BuildLoggerMessage(logFormat).Log("No log_format provided. Using default 'plain'"))
	}

	config.wafInstanceRefs = make(map[string]string, len(config.directives))
	for wafName, wafRules := range config.directives {
		directivesString := strings.Join(wafRules.SimpleDirectives, "\n")
		directivesHash := sha256.Sum256([]byte(directivesString))
		config.wafInstanceRefs[wafName] = fmt.Sprintf("%x", directivesHash)
	}

	if extractorValue, ok := v.AsMap()["trace_route_metadata_extractor"]; ok {
		extractorExpr, ok := extractorValue.(string)
		if !ok {
			return nil, errors.New("trace_route_metadata_extractor must be a string")
		}
		extractorExpr = strings.TrimSpace(extractorExpr)
		if extractorExpr != "" {
			handle, err := routeMetadataExtractorCache.retain(extractorExpr)
			if err != nil {
				return nil, fmt.Errorf("compile trace_route_metadata_extractor: %w", err)
			}
			config.traceRouteMetadataExtractor = handle
		}
	}

	return &config, nil
}

func (p parser) Merge(parentConfig interface{}, childConfig interface{}) interface{} {
	api.LogCriticalf("Merging coraza-waf configs: parent %+v, child %+v", parentConfig, childConfig)
	if parentConfig == nil {
		return childConfig
	}
	if childConfig == nil {
		return parentConfig
	}

	parent, ok := parentConfig.(*configuration)
	if !ok {
		panic("unexpected parent config type")
	}
	child, ok := childConfig.(*configuration)
	if !ok {
		panic("unexpected child config type")
	}

	if child.traceRouteMetadataExtractor == nil && parent.traceRouteMetadataExtractor != nil && parent.traceRouteMetadataExtractor.expr != "" {
		handle, err := routeMetadataExtractorCache.retain(parent.traceRouteMetadataExtractor.expr)
		if err != nil {
			api.LogErrorf("failed to retain trace_route_metadata_extractor expression: %v", err)
		} else {
			child.traceRouteMetadataExtractor = handle
		}
	}
	api.LogCritical("Merged coraza-waf configs successfully")

	return child
}

func errorCallback(error ctypes.MatchedRule) {
	var msg string

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
		// Build attributes for the span event
		attrs := []attribute.KeyValue{
			attribute.Int("coraza.rule.id", error.Rule().ID()),
			attribute.String("coraza.rule.version", error.Rule().Version()),
			attribute.String("coraza.rule.message", error.Message()),
			attribute.String("coraza.rule.severity", error.Rule().Severity().String()),
			attribute.String("coraza.rule.file", error.Rule().File()),
			attribute.String("coraza.rule.uri", error.URI()),
		}

		// Add tags if available
		if len(error.Rule().Tags()) > 0 {
			// Convert tags to a single string for the attribute
			attrs = append(attrs, attribute.StringSlice("coraza.rule.tags", error.Rule().Tags()))
		}

		span.AddEvent("coraza.rule_violation", trace.WithAttributes(attrs...))
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

	if logFormat == "json" {
		line := JSONErrorLogLine{
			TransactionID:  error.TransactionID(),
			RuleSetVersion: error.Rule().Version(),
			Url:            error.URI(),
			Rule: JSONRuleLogEntry{
				RuleID:          error.Rule().ID(),
				Category:        category,
				Severity:        strings.ToUpper(error.Rule().Severity().String()),
				Data:            error.Data(),
				Message:         error.Message(),
				MatchedData:     error.MatchedDatas()[0].Variable().Name(),
				MatchedDataName: error.MatchedDatas()[0].Key(),
				Tags:            error.Rule().Tags(),
			},
			ClientIP:  error.ClientIPAddress(),
			RequestID: xReqID,
		}
		bytes, _ := json.Marshal(line)
		msg = string(bytes)
	} else {
		msg = error.ErrorLog()
	}

	switch error.Rule().Severity() {
	case ctypes.RuleSeverityEmergency:
		api.LogCritical(msg)
	case ctypes.RuleSeverityAlert:
		api.LogCritical(msg)
	case ctypes.RuleSeverityCritical:
		api.LogCritical(msg)
	case ctypes.RuleSeverityError:
		api.LogError(msg)
	case ctypes.RuleSeverityWarning:
		api.LogWarn(msg)
	case ctypes.RuleSeverityNotice:
		api.LogInfo(msg)
	case ctypes.RuleSeverityInfo:
		api.LogInfo(msg)
	case ctypes.RuleSeverityDebug:
		api.LogInfo(msg)
	}
}

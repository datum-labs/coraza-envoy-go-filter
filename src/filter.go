//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// enum for connection state, used to detect websocket connections
type ConnectionState int

const (
	HTTP ConnectionState = iota
	UpgradeWebsocketRequested
	WebsocketConnection
)

type RequestPhase int

const (
	PhaseUnknown RequestPhase = iota
	PhaseRequestHeader
	PhaseRequestBody
	PhaseResponseHeader
	PhaseResponseBody
)

func (p RequestPhase) String() string {
	switch p {
	case PhaseRequestHeader:
		return "request_header"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeader:
		return "response_header"
	case PhaseResponseBody:
		return "response_body"
	default:
		return "unknown"
	}
}

func (connectionState ConnectionState) String() string {
	return connectionStateName[connectionState]
}

var connectionStateName = map[ConnectionState]string{
	HTTP:                      "http",
	UpgradeWebsocketRequested: "websocket upgrade requested",
	WebsocketConnection:       "websocket connection",
}

const HOSTPOSTSEPARATOR string = ":"

var filterTracer = otel.Tracer("coraza/envoy/filter")

const (
	wafOutcomeProcessing = "processing"
	wafOutcomeAllowed    = "allowed"
	wafOutcomeBlocked    = "blocked"
	wafOutcomeError      = "error"
)

type filter struct {
	callbacks                   api.FilterCallbackHandler
	conf                        *configuration
	tx                          types.Transaction
	httpProtocol                string
	isInterruption              bool
	processRequestBody          bool
	processResponseBody         bool
	withNoResponseBodyProcessed bool
	connection                  ConnectionState
	logger                      *BasicLogMessage
	span                        trace.Span
	spanCtx                     context.Context
	wafOutcome                  string

	metadata filterMetadata
}

type filterMetadata struct {
	// Derived from `xds.cluster_name` attribute
	clusterName string

	// Derived from `xds.virtual_host_name` attribute
	virtualHostName string

	// Derived from `xds.route_name` attribute
	routeName string

	// Derived from `xds.filter_chain_name` attribute
	filterChainName string
}

func (f *filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	f.connection = HTTP

	f.logDebug("DecodeHeaders enter", struct{ K, V string }{"f.connection", f.connection.String()})

	var host string
	host = headerMap.Host()
	if len(host) == 0 {
		return api.Continue
	}

	xReqId, exist := headerMap.Get("x-request-id")
	if !exist {
		f.logInfo("Error getting x-request-id header")
		xReqId = ""
	}
	f.startTraceSpan(xReqId, host)
	decodeCtx, decodeSpan := f.startChildSpan(f.spanCtx, "waf.decode_headers")
	if decodeSpan != nil {
		decodeSpan.SetAttributes(attribute.Bool("request.end_stream", endStream))
		defer decodeSpan.End()
	}

	_, getWAFMapsSpan := f.startChildSpan(decodeCtx, "waf.get_waf_maps")
	wafMaps, err := f.conf.getWAFMaps()
	if getWAFMapsSpan != nil {
		getWAFMapsSpan.End()
	}
	if err != nil {
		f.logCritical("failed to initialize waf maps", err)
		f.recordOutcome(wafOutcomeError)
		f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error())))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "waf-init-error")
		return api.LocalReply
	}
	waf, ok := wafMaps[f.conf.defaultDirective]
	if !ok || waf == nil {
		f.logCritical("default directive missing from waf map", struct{ K, V string }{"directive", f.conf.defaultDirective})
		f.recordOutcome(wafOutcomeError)
		f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", "default directive missing")))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "waf-not-configured")
		return api.LocalReply
	}
	if ruleName, ok := f.conf.hostDirectiveMap[host]; ok {
		override, exists := wafMaps[ruleName]
		if !exists || override == nil {
			f.logCritical("host directive missing from waf map", struct{ K, V string }{"directive", ruleName}, struct{ K, V string }{"host", host})
			f.recordOutcome(wafOutcomeError)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", "host directive missing"), attribute.String("waf.directive", ruleName)))
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "waf-not-configured")
			return api.LocalReply
		}
		waf = override
	}

	// the ID of the transaction is set to the ID of the request
	// see errorCallback() in parse.go for more details
	f.tx = waf.NewTransactionWithID(xReqId)
	f.tx.AddRequestHeader("Host", host)
	var server = host
	if strings.Contains(host, HOSTPOSTSEPARATOR) {
		server, _, err = net.SplitHostPort(host)
		if err != nil {
			f.logInfo("Failed to parse server name from Host", struct{ K, V string }{"Host", host}, err)
			f.recordOutcome(wafOutcomeError)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "parse_host")))
			f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
	}
	f.tx.SetServerName(server)
	f.spanAddAttributes(attribute.String("server.name", server))
	tx := f.tx

	if tx.IsRuleEngineOff() {
		f.recordOutcome(wafOutcomeAllowed)
		f.spanAddEvent("waf.rule_engine_off")
		return api.Continue
	}
	srcIP, srcPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamRemoteAddress())
	srcPort, err := strconv.Atoi(srcPortString)
	if err != nil {
		f.logInfo("RemotePort formatting error", err)
		f.recordOutcome(wafOutcomeError)
		f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "parse_remote_port")))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	destIP, destPortString, _ := net.SplitHostPort(f.callbacks.StreamInfo().DownstreamLocalAddress())
	destPort, err := strconv.Atoi(destPortString)
	if err != nil {
		f.logInfo("LocalPort formatting error", err)
		f.recordOutcome(wafOutcomeError)
		f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "parse_local_port")))
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	connAttrs := []attribute.KeyValue{
		attribute.String("client.address", srcIP),
		attribute.Int("client.port", srcPort),
		attribute.String("server.address", destIP),
		attribute.Int("server.port", destPort),
	}
	_, processConnSpan := f.startChildSpan(decodeCtx, "waf.process_connection")
	if processConnSpan != nil {
		processConnSpan.SetAttributes(connAttrs...)
	}
	tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	finishSpan(processConnSpan, nil)
	f.spanAddAttributes(connAttrs...)
	path := headerMap.Path()
	method := headerMap.Method()
	protocol, ok := f.callbacks.StreamInfo().Protocol()
	if !ok {
		f.logWarn("Protocol not set")
		protocol = "HTTP/2.0"
	}
	f.httpProtocol = protocol
	uriAttrs := []attribute.KeyValue{
		attribute.String("http.method", method),
		attribute.String("http.target", path),
		attribute.String("http.protocol", protocol),
	}
	_, processURISpan := f.startChildSpan(decodeCtx, "waf.process_uri")
	if processURISpan != nil {
		processURISpan.SetAttributes(uriAttrs...)
	}
	tx.ProcessURI(path, method, protocol)
	finishSpan(processURISpan, nil)
	f.spanAddAttributes(uriAttrs...)

	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerCount := 0
	headerMap.Range(func(key, value string) bool {
		headerCount++
		// check for WS upgrade request
		if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
			upgrade_websocket_header = true
		}
		if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
			connection_upgrade_header = true

		}
		tx.AddRequestHeader(key, value)
		return true
	})
	if decodeSpan != nil {
		decodeSpan.SetAttributes(attribute.Int("http.request.header_count", headerCount))
	}
	if upgrade_websocket_header && connection_upgrade_header {
		f.logDebug("Websocket upgrade request detected")
		f.connection = UpgradeWebsocketRequested
		f.spanAddAttributes(attribute.Bool("waf.request.websocket_upgrade", true))
		f.spanAddEvent("waf.request.websocket_upgrade_requested")
	}
	_, processHeadersSpan := f.startChildSpan(decodeCtx, "waf.process_request_headers")
	if processHeadersSpan != nil {
		processHeadersSpan.SetAttributes(attribute.Int("http.request.header_count", headerCount))
	}
	interruption := tx.ProcessRequestHeaders()
	if interruption != nil && processHeadersSpan != nil {
		processHeadersSpan.SetAttributes(attribute.Bool("waf.interruption", true))
	}
	finishSpan(processHeadersSpan, nil)
	if interruption != nil {
		f.handleInterruption(PhaseRequestHeader, interruption)
		return api.LocalReply
	}
	return api.Continue
}

func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.logDebug("DecodeData enter", struct{ K, V string }{"f.connection", f.connection.String()})
	initialBufferLen := buffer.Len()
	dataCtx, dataSpan := f.startChildSpan(f.spanCtx, "waf.decode_data")
	if dataSpan != nil {
		dataSpan.SetAttributes(
			attribute.Bool("request.end_stream", endStream),
			attribute.Int("request.buffer.len", initialBufferLen),
		)
		defer dataSpan.End()
	}

	if f.isInterruption {
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "interruption-already-handled")
		return api.LocalReply
	}
	if f.processRequestBody {
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !tx.IsRequestBodyAccessible() {
		f.logDebug("Skipping request body processing, SecRequestBodyAccess is off")
		f.spanAddAttributes(attribute.Bool("waf.request_body.accessible", false))
		f.processRequestBody = true
		_, processBodySpan := f.startChildSpan(dataCtx, "waf.process_request_body")
		if processBodySpan != nil {
			processBodySpan.SetAttributes(attribute.String("waf.request_body.reason", "access_disabled"))
		}
		interruption, err := tx.ProcessRequestBody()
		spanAttrs := []attribute.KeyValue{}
		if interruption != nil {
			spanAttrs = append(spanAttrs, attribute.Bool("waf.interruption", true))
		}
		finishSpan(processBodySpan, err, spanAttrs...)
		if err != nil {
			f.logInfo("Failed to process request body", err)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "process_request_body")))
			return api.Continue
		}
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
		return api.Continue
	}
	bodySize := buffer.Len()
	f.logTrace("Processing incoming request data", struct{ K, V string }{"size", strconv.Itoa(bodySize)})
	if bodySize > 0 {
		bytes := buffer.Bytes()
		_, writeBodySpan := f.startChildSpan(dataCtx, "waf.write_request_body")
		if writeBodySpan != nil {
			writeBodySpan.SetAttributes(attribute.Int("chunk.size", bodySize))
		}
		interruption, buffered, err := tx.WriteRequestBody(bytes)
		f.logTrace("Buffered request data", struct{ K, V string }{"size", strconv.Itoa(buffered)})
		spanAttrs := []attribute.KeyValue{attribute.Int("chunk.buffered", buffered)}
		if interruption != nil {
			spanAttrs = append(spanAttrs, attribute.Bool("waf.interruption", true))
		}
		finishSpan(writeBodySpan, err, spanAttrs...)
		if err != nil {
			f.logInfo("Failed to write request body", err)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "write_request_body")))
			return api.Continue
		}

		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
	}
	if endStream {
		f.processRequestBody = true
		_, processBodySpan := f.startChildSpan(dataCtx, "waf.process_request_body")
		if processBodySpan != nil {
			processBodySpan.SetAttributes(attribute.String("waf.request_body.reason", "end_stream"))
		}
		interruption, err := tx.ProcessRequestBody()
		spanAttrs := []attribute.KeyValue{}
		if interruption != nil {
			spanAttrs = append(spanAttrs, attribute.Bool("waf.interruption", true))
		}
		finishSpan(processBodySpan, err, spanAttrs...)
		if err != nil {
			f.logInfo("Failed to process request body", err)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "process_request_body_end")))
			return api.Continue
		}
		if interruption != nil {
			f.handleInterruption(PhaseRequestBody, interruption)
			return api.LocalReply
		}
		f.spanAddEvent("waf.request.body_processed")
		return api.Continue
	}

	// only buffer the body if it is an HTTP connection
	if f.connection == HTTP {
		f.logDebug("Buffering request body data")
		return api.StopAndBuffer
	}
	return api.Continue
}

func (f *filter) DecodeTrailers(trailerMap api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	f.logDebug("Encode headers enter", struct{ K, V string }{"f.connection", f.connection.String()})
	headersCtx, headersSpan := f.startChildSpan(f.spanCtx, "waf.encode_headers")
	if headersSpan != nil {
		headersSpan.SetAttributes(attribute.Bool("response.end_stream", endStream))
		defer headersSpan.End()
	}
	if f.isInterruption {
		f.logDebug("Interruption already handled, sending downstream the local response")
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	if tx.IsRuleEngineOff() {
		f.recordOutcome(wafOutcomeAllowed)
		f.spanAddEvent("waf.rule_engine_off")
		return api.Continue
	}
	if !f.processRequestBody {
		f.logDebug("ProcessRequestBody in phase3")
		f.processRequestBody = true
		_, processBodySpan := f.startChildSpan(headersCtx, "waf.process_request_body")
		if processBodySpan != nil {
			processBodySpan.SetAttributes(attribute.String("waf.request_body.reason", "phase3"))
		}
		interruption, err := tx.ProcessRequestBody()
		spanAttrs := []attribute.KeyValue{}
		if interruption != nil {
			spanAttrs = append(spanAttrs, attribute.Bool("waf.interruption", true))
		}
		finishSpan(processBodySpan, err, spanAttrs...)
		if err != nil {
			f.logInfo("Failed to process request body", err)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "process_request_body_phase3")))
			return api.Continue
		}
		if interruption != nil {
			f.handleInterruption(PhaseResponseHeader, interruption)
			return api.LocalReply
		}
	}
	code, b := f.callbacks.StreamInfo().ResponseCode()
	if !b {
		code = 0
	}
	f.spanAddAttributes(attribute.Int("http.status_code", int(code)))
	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerMap.Range(func(key, value string) bool {
		// check for WS upgrade response
		if f.connection == UpgradeWebsocketRequested {
			if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
				upgrade_websocket_header = true
			}
			if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
				connection_upgrade_header = true

			}
		}
		tx.AddResponseHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		f.logDebug("Websocket upgrade response detected")
		f.connection = WebsocketConnection
		f.spanAddAttributes(attribute.Bool("waf.response.websocket_upgrade", true))
		f.spanAddEvent("waf.response.websocket_upgrade_accepted")
	}
	_, processRespHeadersSpan := f.startChildSpan(headersCtx, "waf.process_response_headers")
	if processRespHeadersSpan != nil {
		processRespHeadersSpan.SetAttributes(
			attribute.Int("http.status_code", int(code)),
			attribute.String("http.protocol", f.httpProtocol),
		)
	}
	interruption := tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil && processRespHeadersSpan != nil {
		processRespHeadersSpan.SetAttributes(attribute.Bool("waf.interruption", true))
	}
	finishSpan(processRespHeadersSpan, nil)
	if interruption != nil {
		f.handleInterruption(PhaseResponseHeader, interruption)
		return api.LocalReply
	}

	/* if this is not the end of the stream (i.e there is a body) and response
	 * body processing is enabled, we need to buffer the headers to avoid envoy
	 * already sending them downstream to the client before the body processing
	 * eventually changes the status code
	 */
	if !endStream && tx.IsResponseBodyAccessible() && f.connection == HTTP {
		f.logDebug("Buffering response headers")
		f.spanAddEvent("waf.response.headers_buffered")
		return api.StopAndBuffer
	}

	f.spanAddEvent("waf.response.headers_processed")
	return api.Continue
}

func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	f.logDebug("EncodeData enter", struct{ K, V string }{"f.connection", f.connection.String()})
	initialRespBufferLen := buffer.Len()
	encodeDataCtx, encodeDataSpan := f.startChildSpan(f.spanCtx, "waf.encode_data")
	if encodeDataSpan != nil {
		encodeDataSpan.SetAttributes(
			attribute.Bool("response.end_stream", endStream),
			attribute.Int("response.buffer.len", initialRespBufferLen),
		)
		defer encodeDataSpan.End()
	}

	// immediately return if its a websocket request as we can't handle the binary body data
	if f.connection == WebsocketConnection {
		f.logDebug("Skip response body processing (websocket connection)")
		f.spanAddEvent("waf.response.websocket_bypass")
		return api.Continue
	}
	if f.isInterruption {
		f.callbacks.EncoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}
	if f.withNoResponseBodyProcessed {
		f.spanAddEvent("waf.response.body_processing_disabled")
		return api.Continue
	}
	if f.tx == nil {
		return api.Continue
	}
	tx := f.tx
	bodySize := buffer.Len()
	if tx.IsRuleEngineOff() {
		return api.Continue
	}
	f.logTrace("Processing incoming response data", struct{ K, V string }{"size", strconv.Itoa(bodySize)})
	if !tx.IsResponseBodyAccessible() {
		f.logDebug("Skipping response body processing, SecResponseBodyAccess is off")
		if !f.withNoResponseBodyProcessed {
			// According to documentation, it is recommended to call this method even if it has no body.
			// It permits to execute rules belonging to request body phase, but not necesarily processing the response body.
			_, processRespBodySpan := f.startChildSpan(encodeDataCtx, "waf.process_response_body")
			if processRespBodySpan != nil {
				processRespBodySpan.SetAttributes(attribute.String("waf.response_body.reason", "access_disabled"))
			}
			interruption, err := tx.ProcessResponseBody()
			spanAttrs := []attribute.KeyValue{}
			if interruption != nil {
				spanAttrs = append(spanAttrs, attribute.Bool("waf.interruption", true))
			}
			finishSpan(processRespBodySpan, err, spanAttrs...)
			f.withNoResponseBodyProcessed = true
			f.processResponseBody = true
			f.spanAddAttributes(attribute.Bool("waf.response_body.accessible", false))
			if err != nil {
				f.logInfo("Failed to process response body", err)
				f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "process_response_body")))
				return api.Continue
			}
			if interruption != nil {
				f.handleInterruption(PhaseResponseBody, interruption)
				return api.LocalReply
			}
		}
		return api.Continue
	}
	if bodySize > 0 {
		ResponseBodyBuffer := buffer.Bytes()
		interruption, buffered, err := tx.WriteResponseBody(ResponseBodyBuffer)
		f.logTrace("Buffered response body data", struct{ K, V string }{"size", strconv.Itoa(buffered)})
		if encodeDataSpan != nil {
			encodeDataSpan.SetAttributes(
				attribute.Int("waf.response.chunk.size", bodySize),
				attribute.Int("waf.response.chunk.buffered", buffered),
			)
		}
		if err != nil {
			f.logInfo("Failed to write response body", err)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "write_response_body")))
			return api.Continue
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.handleInterruption(PhaseResponseBody, interruption)
			return api.LocalReply
		}
	}
	if endStream {
		f.processResponseBody = true
		_, processRespBodySpan := f.startChildSpan(encodeDataCtx, "waf.process_response_body")
		if processRespBodySpan != nil {
			processRespBodySpan.SetAttributes(attribute.String("waf.response_body.reason", "end_stream"))
		}
		interruption, err := tx.ProcessResponseBody()
		spanAttrs := []attribute.KeyValue{}
		if interruption != nil {
			spanAttrs = append(spanAttrs, attribute.Bool("waf.interruption", true))
		}
		finishSpan(processRespBodySpan, err, spanAttrs...)
		if err != nil {
			f.logInfo("failed to process response body", err)
			f.spanAddEvent("waf.error", trace.WithAttributes(attribute.String("error.message", err.Error()), attribute.String("waf.stage", "process_response_body_end")))
			return api.Continue
		}
		if interruption != nil {
			buffer.Set(bytes.Repeat([]byte("\x00"), bodySize))
			f.handleInterruption(PhaseResponseBody, interruption)
			return api.LocalReply
		}
		f.spanAddEvent("waf.response.body_processed")
		return api.Continue
	}
	return api.StopAndBuffer
}

func (f *filter) EncodeTrailers(trailerMap api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

func (f *filter) OnLog(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {
}
func (f *filter) OnLogDownstreamPeriodic(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {
}
func (f *filter) OnLogDownstreamStart(api.RequestHeaderMap) {}
func (f *filter) OnStreamComplete()                         {}

func (f *filter) OnDestroy(reason api.DestroyReason) {
	tx := f.tx
	if tx != nil {
		if !f.processResponseBody {
			f.logDebug("Running ProcessResponseBody in OnHttpStreamDone, triggered actions will not be enforced. Further logs are for detection only purposes")
			f.processResponseBody = true
			_, err := tx.ProcessResponseBody()
			if err != nil {
				f.logInfo("failed to process response body in OnDestroy", err)
			}
		}
		f.spanAddEvent("waf.transaction.process_logging")
		f.tx.ProcessLogging()
		_ = f.tx.Close()
		f.logInfo("Transaction finished")
	}
	f.endSpanWithReason(reason)
}

func (f *filter) handleInterruption(phase RequestPhase, interruption *types.Interruption) {
	f.isInterruption = true
	f.logInfo("Transaction interrupted",
		struct{ K, V string }{"phase", phase.String()},
		struct{ K, V string }{"ruleID", strconv.Itoa(interruption.RuleID)},
		struct{ K, V string }{"action", interruption.Action},
		struct{ K, V string }{"status", strconv.Itoa(interruption.Status)})

	f.recordOutcome(wafOutcomeBlocked)
	f.spanAddAttributes(
		attribute.Int("waf.rule_id", interruption.RuleID),
		attribute.String("waf.rule_action", interruption.Action),
		attribute.Int("http.status_code", interruption.Status),
		attribute.String("waf.interruption.phase", phase.String()),
	)
	f.spanAddEvent("waf.interruption", trace.WithAttributes(
		attribute.Int("waf.rule_id", interruption.RuleID),
		attribute.String("waf.rule_action", interruption.Action),
		attribute.Int("http.status_code", interruption.Status),
		attribute.String("waf.interruption.phase", phase.String()),
	))

	switch phase {
	case PhaseRequestHeader, PhaseRequestBody:
		f.callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	case PhaseResponseHeader, PhaseResponseBody:
		f.callbacks.EncoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	}
}

func (f *filter) startTraceSpan(xReqId, host string) {
	if f.spanIsActive() {
		return
	}
	ctx, span := filterTracer.Start(context.Background(), "waf.request", trace.WithSpanKind(trace.SpanKindServer))

	f.span = span
	f.spanCtx = ctx
	f.recordOutcome(wafOutcomeProcessing)
	attrs := []attribute.KeyValue{
		attribute.String("http.host", host),
		attribute.String("waf.metadata.cluster_name", f.metadata.clusterName),
		attribute.String("waf.metadata.virtual_host_name", f.metadata.virtualHostName),
		attribute.String("waf.metadata.route_name", f.metadata.routeName),
		attribute.String("waf.metadata.filter_chain_name", f.metadata.filterChainName),
	}
	if xReqId != "" {
		attrs = append(attrs, attribute.String("waf.request_id", xReqId))
	}
	f.span.SetAttributes(attrs...)
	f.span.AddEvent("waf.span_started")
}

func (f *filter) spanIsActive() bool {
	return f.span != nil && f.span.SpanContext().IsValid()
}

func (f *filter) spanAddAttributes(attrs ...attribute.KeyValue) {
	if !f.spanIsActive() {
		return
	}
	f.span.SetAttributes(attrs...)
}

func (f *filter) spanAddEvent(name string, options ...trace.EventOption) {
	if !f.spanIsActive() {
		return
	}
	f.span.AddEvent(name, options...)
}

func (f *filter) startChildSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if !f.spanIsActive() {
		return ctx, nil
	}
	if len(opts) == 0 {
		opts = append(opts, trace.WithSpanKind(trace.SpanKindInternal))
	}
	ctx, span := filterTracer.Start(ctx, name, opts...)
	return ctx, span
}

func finishSpan(span trace.Span, err error, attrs ...attribute.KeyValue) {
	if span == nil {
		return
	}
	if err != nil {
		span.RecordError(err)
	}
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	span.End()
}

func (f *filter) recordOutcome(outcome string) {
	f.wafOutcome = outcome
	f.spanAddAttributes(attribute.String("waf.outcome", outcome))
}

func (f *filter) endSpanWithReason(reason api.DestroyReason) {
	if !f.spanIsActive() {
		return
	}
	if f.wafOutcome == "" || f.wafOutcome == wafOutcomeProcessing {
		f.recordOutcome(wafOutcomeAllowed)
	}
	f.spanAddAttributes(attribute.String("envoy.destroy_reason", fmt.Sprintf("%v", reason)))
	f.span.AddEvent("waf.span_finished")
	f.span.End()
	f.span = nil
	f.spanCtx = nil
}

/* helpers for easy logging */
func (f *filter) logTrace(parts ...interface{}) {
	f.callbacks.Log(api.Trace, f.logger.Log(parts...))
}
func (f *filter) logDebug(parts ...interface{}) {
	f.callbacks.Log(api.Debug, f.logger.Log(parts...))
}
func (f *filter) logInfo(parts ...interface{}) {
	f.callbacks.Log(api.Info, f.logger.Log(parts...))
}
func (f *filter) logWarn(parts ...interface{}) {
	f.callbacks.Log(api.Warn, f.logger.Log(parts...))
}
func (f *filter) logError(parts ...interface{}) {
	f.callbacks.Log(api.Error, f.logger.Log(parts...))
}
func (f *filter) logCritical(parts ...interface{}) {
	f.callbacks.Log(api.Critical, f.logger.Log(parts...))
}

func main() {
}

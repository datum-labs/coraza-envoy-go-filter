// Copyright © 2023 Axkea, spacewander
// Copyright © 2025 United Security Providers AG, Switzerland
// Copyright © 2025 Datum Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

package filter

import (
	"context"
	"coraza-waf/internal/config"
	"coraza-waf/internal/logging"
	"coraza-waf/internal/telemetry"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const HOSTPOSTSEPARATOR string = ":"

const (
	wafOutcomeProcessing = "processing"
	wafOutcomeAllowed    = "allowed"
	wafOutcomeBlocked    = "blocked"
	wafOutcomeError      = "error"
)

// Envoy's golang HTTP filter drops the body of a response-phase SendLocalReply
// when the body is empty and the upstream response headers are already
// committed (envoyproxy/envoy#39775): the client gets a Content-Length from the
// host local_reply_config but zero body bytes, seen as a truncated 5xx. Passing
// a non-empty body with an explicit Content-Type makes Envoy write a complete
// response and recompute Content-Length. Only the encode (response) path needs
// this; the decode (request) path recomputes correctly with an empty body.
const (
	responseBlockedReplyBody = "Request blocked by security policy.\n"
	responseErrorReplyBody   = "Internal server error.\n"
)

// FilterMetadata holds metadata extracted from Envoy xDS properties and route metadata.
type FilterMetadata struct {
	ClusterName          string
	VirtualHostName      string
	RouteName            string
	FilterChainName      string
	TraceRouteAttributes map[string]string
}

type Filter struct {
	api.PassThroughStreamFilter

	Callbacks      api.FilterCallbackHandler
	Config         config.Configuration
	Metadata       FilterMetadata
	tx             types.Transaction
	wasInterrupted bool
	httpProtocol   string
	connection     connectionState
	requestId      string

	// Tracing fields
	span       trace.Span
	spanCtx    context.Context
	wafOutcome string
}

func (f *Filter) DecodeHeaders(headerMap api.RequestHeaderMap, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "DecodeHeaders")
	requestId, exist := headerMap.Get("x-request-id")
	if !exist {
		logger.Debug("x-request-id header missing")
		requestId = "<unknown>"
	}
	f.requestId = requestId
	logger = logger.With("request-id", requestId)
	f.connection = connectionStateHttp
	host := headerMap.Host()
	if len(host) == 0 {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return api.LocalReply
	}

	// Start trace span
	f.startTraceSpan(requestId, host)
	decodeCtx, decodeSpan := f.startChildSpan(f.spanCtx, "http.request.decode.headers")
	if decodeSpan != nil {
		decodeSpan.SetAttributes(attribute.Bool("http.request.end_stream", endStream))
		defer decodeSpan.End()
	}

	// Initialize the WAF transaction
	err := f.initializeTx(logger, headerMap, host)
	if err != nil {
		logger.Error("could not initialize transaction", "error", err.Error())
		f.recordOutcome(wafOutcomeError)
		return api.LocalReply
	}
	if f.tx.IsRuleEngineOff() {
		f.recordOutcome(wafOutcomeAllowed)
		return api.Continue
	}
	// Process connection (will not block)
	srcIP, srcPort, err := f.splitHostPort(f.Callbacks.StreamInfo().DownstreamRemoteAddress())
	if err != nil {
		logger.Error("could not parse IP and port for remote address", "error", err.Error())
		f.recordOutcome(wafOutcomeError)
		return api.LocalReply
	}
	destIP, destPort, err := f.splitHostPort(f.Callbacks.StreamInfo().DownstreamLocalAddress())
	if err != nil {
		logger.Error("could not parse IP and port for local address", "error", err.Error())
		f.recordOutcome(wafOutcomeError)
		return api.LocalReply
	}

	connAttrs := []attribute.KeyValue{
		attribute.String("client.address", srcIP),
		attribute.Int("client.port", srcPort),
		attribute.String("server.address", destIP),
		attribute.Int("server.port", destPort),
	}
	_, processConnSpan := f.startChildSpan(decodeCtx, "http.connection.process")
	if processConnSpan != nil {
		processConnSpan.SetAttributes(connAttrs...)
	}
	f.tx.ProcessConnection(srcIP, srcPort, destIP, destPort)
	finishSpan(processConnSpan, nil)
	f.spanAddAttributes(connAttrs...)

	// Process URI (will not block)
	path := headerMap.Path()
	method := headerMap.Method()
	if strings.EqualFold(method, "connect") {
		f.connection = connectionStateHttpTunnel
	}
	protocol, ok := f.Callbacks.StreamInfo().Protocol()
	if !ok {
		logger.Warn("Protocol not set")
		protocol = "HTTP/2.0"
	}
	f.httpProtocol = protocol

	uriAttrs := []attribute.KeyValue{
		attribute.String("http.method", method),
		attribute.String("http.target", path),
		attribute.String("http.protocol", protocol),
	}
	_, processURISpan := f.startChildSpan(decodeCtx, "http.request.uri.process")
	if processURISpan != nil {
		processURISpan.SetAttributes(uriAttrs...)
	}
	f.tx.ProcessURI(path, method, protocol)
	finishSpan(processURISpan, nil)
	f.spanAddAttributes(uriAttrs...)

	// Process request headers (might block)
	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerMap.Range(func(key, value string) bool {
		// check for WS upgrade request
		if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
			upgrade_websocket_header = true
		}
		if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
			connection_upgrade_header = true
		}
		f.tx.AddRequestHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		logger.Debug("Websocket upgrade request detected")
		f.connection = connectionStateUpgradeWebsocketRequested
		f.spanAddAttributes(attribute.Bool("http.request.websocket_upgrade", true))
	}

	_, processHeadersSpan := f.startChildSpan(decodeCtx, "http.request.headers.process")
	interruption := f.tx.ProcessRequestHeaders()
	if interruption != nil && processHeadersSpan != nil {
		processHeadersSpan.SetAttributes(attribute.Bool("coraza.interruption", true))
	}
	finishSpan(processHeadersSpan, nil)
	if interruption != nil {
		f.handleInterruption(logger, PhaseRequestHeader, interruption)
		return api.LocalReply
	}

	if endStream {
		err := f.validateRequestBody(logger)
		if err != nil {
			logger.Error("request validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}

	if f.tx.IsRequestBodyAccessible() && f.connection.IsHttp() {
		logger.Debug("Buffering request body data")
		return api.StopAndBuffer
	}

	return api.StopAndBufferWatermark
}

func (f *Filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "DecodeData").With("request-id", f.requestId)
	if f.wasInterrupted {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "interruption-already-handled")
		return api.LocalReply
	}
	if f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	if !f.tx.IsRequestBodyAccessible() {
		logger.Debug("Skipping request body processing, SecRequestBodyAccess is off")
		err := f.validateRequestBody(logger)
		if err != nil {
			logger.Error("request validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}
	logger.Debug("Processing incoming request data", "size", buffer.Len())
	if buffer.Len() > 0 {
		// Write request body into waf
		interruption, buffered, err := f.tx.WriteRequestBody(buffer.Bytes())
		logger.Debug("Buffered request data", "size", buffered)
		if err != nil {
			logger.Error("Failed to write request body", "error", err)
			/* processing error, block the request to prevent further processing */
			f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
			return api.LocalReply
		}
		/* WriteRequestBody triggers ProcessRequestBody if the bodylimit (SecRequestBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by request body processing.
		 */
		if interruption != nil {
			f.handleInterruption(logger, PhaseRequestBody, interruption)
			return api.LocalReply
		}
	}

	if endStream {
		err := f.validateRequestBody(logger)
		if err != nil {
			logger.Error("request validation failed", "error", err.Error())
			return api.LocalReply
		}
	}
	return api.Continue
}

func (f *Filter) EncodeHeaders(headerMap api.ResponseHeaderMap, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "EncodeHeaders")
	if f.wasInterrupted {
		logger.Debug("Interruption already handled, sending downstream the local response")
		return api.Continue
	}
	// the nil check here MUST NEVER be removed
	// there are cases (e.g. malformed HTTP request) where envoy will automatically
	// jump from the decoding phase to the encoding phase
	if f.tx == nil || f.tx.IsRuleEngineOff() {
		return api.Continue
	}
	logger = logger.With("request-id", f.requestId)
	code, b := f.Callbacks.StreamInfo().ResponseCode()
	if !b {
		code = 0
	}
	f.spanAddAttributes(attribute.Int("http.status_code", int(code)))
	// Process response headers (might block)
	upgrade_websocket_header := false
	connection_upgrade_header := false
	headerMap.Range(func(key, value string) bool {
		// check for WS upgrade response
		if f.connection.IsWebsocketUpgradeRequested() {
			if key == "upgrade" && strings.Contains(strings.ToLower(value), "websocket") {
				upgrade_websocket_header = true
			}
			if key == "connection" && strings.Contains(strings.ToLower(value), "upgrade") {
				connection_upgrade_header = true

			}
		}
		f.tx.AddResponseHeader(key, value)
		return true
	})
	if upgrade_websocket_header && connection_upgrade_header {
		logger.Debug("Websocket upgrade request detected")
		f.connection = connectionStateWebsocketConnection
		f.spanAddAttributes(attribute.Bool("http.response.websocket_upgrade", true))
	}
	interruption := f.tx.ProcessResponseHeaders(int(code), f.httpProtocol)
	if interruption != nil {
		f.handleInterruption(logger, PhaseResponseHeader, interruption)
		return api.LocalReply
	}

	if endStream {
		err := f.validateResponseBody(logger)
		if err != nil {
			logger.Error("response validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}

	// No response-body inspection needed: stream through.
	if !f.tx.IsResponseBodyAccessible() {
		return api.Continue
	}
	// Hold the upstream response headers until the response-body verdict is
	// known. StopAndBufferWatermark buffers body chunks with backpressure while
	// keeping header iteration stopped (headers are NOT committed downstream) so
	// a later response-body-phase interruption can still emit a branded local
	// reply. Returning Continue here (as the previous code did on non-final
	// EncodeData chunks) commits the 200 headers, after which any block is
	// undeliverable — the client gets the origin 200 (silent WAF bypass) or a
	// mid-stream reset (envoyproxy/envoy#39775). EncodeData releases the held
	// headers once coraza reaches SecResponseBodyLimit or the body ends.
	return api.StopAndBufferWatermark
}

func (f *Filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	logger := logging.GetLogger().With("action", "EncodeData").With("request-id", f.requestId)
	// the nil check here MUST NEVER be removed
	// there are cases (e.g. malformed HTTP request) where envoy will automatically
	// jump from the decoding phase to the encoding phase
	if f.tx == nil || f.tx.IsRuleEngineOff() || f.connection.IsWebsocket() {
		if f.connection.IsWebsocket() {
			logger.Debug("Skip response body processing (websocket connection)")
		}
		return api.Continue
	}
	if f.wasInterrupted {
		f.sendResponseLocalReply(http.StatusForbidden, responseBlockedReplyBody)
		return api.LocalReply
	}
	logger.Debug("Processing incoming response data", "size", buffer.Len())
	if !f.tx.IsResponseBodyAccessible() {
		logger.Debug("Skipping response body processing, SecResponseBodyAccess is off")
		err := f.validateResponseBody(logger)
		if err != nil {
			logger.Error("response validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}
	if buffer.Len() > 0 {
		// Write response body into waf
		interruption, buffered, err := f.tx.WriteResponseBody(buffer.Bytes())
		logger.Debug("Buffered response body data", "size", buffered)
		if err != nil {
			logger.Error("Failed to write response body", "error", err)
			return api.Continue
		}
		/* WriteResponseBody triggers ProcessResponseBody if the bodylimit (SecResponseBodyLimit) is reached.
		 * This means if we receive an interruption here it was evaluated and interrupted by response body processing.
		 */
		if interruption != nil {
			f.handleInterruption(logger, PhaseResponseBody, interruption)
			return api.LocalReply
		}
		// coraza accepted fewer bytes than we handed it: SecResponseBodyLimit is
		// reached and it processed the buffered portion without blocking. It will
		// not inspect any more of the body, so stop holding — release the
		// headers + buffered data and stream the remainder. Continuing to buffer
		// past this point would exceed the proxy's per_connection_buffer_limit
		// and surface as response_payload_too_large (500). SecResponseBodyLimit
		// must therefore be <= the gateway per_connection_buffer_limit_bytes.
		if buffered < buffer.Len() {
			logger.Debug("response body limit reached without interruption; releasing", "inspected", buffered)
			return api.Continue
		}
	}
	// We reached the end of the body: evaluate and either block or release.
	if endStream {
		err := f.validateResponseBody(logger)
		if err != nil {
			logger.Error("response validation failed", "error", err.Error())
			return api.LocalReply
		}
		return api.Continue
	}

	// More body to come. Keep the headers held and keep buffering so a
	// later response-body-phase interruption can still emit a local reply;
	// streaming (Continue) here commits the upstream headers and makes the
	// block undeliverable (envoyproxy/envoy#39775). coraza bounds the buffer
	// at SecResponseBodyLimit.
	return api.StopAndBufferWatermark
}

func (f *Filter) OnDestroy(reason api.DestroyReason) {
	logger := logging.GetLogger().With("action", "OnDestroy").With("request-id", f.requestId)
	if f.tx == nil {
		return
	}

	f.spanAddEvent("coraza.transaction.process_logging")
	f.tx.ProcessLogging()
	_ = f.tx.Close()
	logger.Info("Transaction finished")
	f.endSpanWithReason(reason)
}

func (f *Filter) initializeTx(logger logging.Logger, headerMap api.RequestHeaderMap, host string) error {
	xReqId, exist := headerMap.Get("x-request-id")
	if !exist {
		logger.Error("Error getting x-request-id header")
		xReqId = ""
	}
	directiveName := f.Config.DefaultDirective
	if d, ok := f.Config.HostDirectiveMap[host]; ok {
		directiveName = d
	} else if hostWithoutPort, _, err := net.SplitHostPort(host); err == nil {
		if d, ok := f.Config.HostDirectiveMap[hostWithoutPort]; ok {
			directiveName = d
		}
	}

	directive, ok := f.Config.Directives[directiveName]
	if !ok {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
		return fmt.Errorf("directive %s not found", directiveName)
	}

	// Resolve WAF instance from cache
	waf, err := config.WafCache.Get(f.Config.WafInstanceRefs[directiveName], func() (coraza.WAF, error) {
		wafConfig := coraza.NewWAFConfig().
			WithErrorCallback(config.ErrorCallback).
			WithRootFS(config.Root).
			WithDirectives(strings.Join(directive.SimpleDirectives, "\n"))
		return coraza.NewWAF(wafConfig)
	})
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
		return fmt.Errorf("failed to get WAF instance: %w", err)
	}

	// Use experimental API to pass span context into the transaction
	if wafOpts, ok := waf.(experimental.WAFWithOptions); ok {
		f.tx = wafOpts.NewTransactionWithOptions(experimental.Options{
			ID:      xReqId,
			Context: f.spanCtx,
		})
	} else {
		f.tx = waf.NewTransactionWithID(xReqId)
	}

	f.tx.AddRequestHeader("Host", host)
	var server = host
	if strings.Contains(host, HOSTPOSTSEPARATOR) {
		server, _, err = f.splitHostPort(host)
		if err != nil {
			f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusForbidden, "", map[string][]string{}, 0, "")
			return fmt.Errorf("failed to parse server name from Host: %s", err)
		}
	}
	f.tx.SetServerName(server)
	f.spanAddAttributes(attribute.String("server.name", server))

	return nil
}

func (f *Filter) validateRequestBody(logger logging.Logger) error {
	interruption, err := f.tx.ProcessRequestBody()
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusInternalServerError, "", map[string][]string{}, 0, "")
		return errors.New("failed to process request body")
	}
	if interruption != nil {
		f.handleInterruption(logger, PhaseRequestBody, interruption)
		return errors.New("found interruption")
	}

	return nil
}

func (f *Filter) validateResponseBody(logger logging.Logger) error {
	interruption, err := f.tx.ProcessResponseBody()
	if err != nil {
		f.sendResponseLocalReply(http.StatusInternalServerError, responseErrorReplyBody)
		return errors.New("failed to process response body")
	}
	if interruption != nil {
		f.handleInterruption(logger, PhaseResponseBody, interruption)
		return errors.New("found interruption")
	}

	return nil
}

func (f *Filter) handleInterruption(logger logging.Logger, phase phase, interruption *types.Interruption) {
	f.wasInterrupted = true
	logger.Info(
		"Transaction interrupted",
		"phase", phase.String(),
		"ruleID", interruption.RuleID,
		"action", interruption.Action,
		"status", interruption.Status,
	)

	f.recordOutcome(wafOutcomeBlocked)
	f.spanAddAttributes(
		attribute.Int("coraza.rule.id", interruption.RuleID),
		attribute.String("coraza.rule.action", interruption.Action),
		attribute.Int("http.status_code", interruption.Status),
		attribute.String("coraza.interruption.phase", phase.String()),
	)
	f.spanAddEvent("coraza.interruption", trace.WithAttributes(
		attribute.Int("coraza.rule.id", interruption.RuleID),
		attribute.String("coraza.rule.action", interruption.Action),
		attribute.Int("http.status_code", interruption.Status),
		attribute.String("coraza.interruption.phase", phase.String()),
	))

	switch phase {
	case PhaseRequestHeader, PhaseRequestBody:
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(interruption.Status, "", map[string][]string{}, 0, "")
	case PhaseResponseHeader, PhaseResponseBody:
		f.sendResponseLocalReply(interruption.Status, responseBlockedReplyBody)
	}
}

func (f *Filter) sendResponseLocalReply(status int, body string) {
	f.Callbacks.EncoderFilterCallbacks().SendLocalReply(
		status,
		body,
		map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
		0,
		"",
	)
}

func (f *Filter) splitHostPort(hostPortCombination string) (string, int, error) {
	ip, portString, err := net.SplitHostPort(hostPortCombination)
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return "", 0, fmt.Errorf("address formatting err: %s", err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		f.Callbacks.DecoderFilterCallbacks().SendLocalReply(http.StatusBadRequest, "", map[string][]string{}, 0, "")
		return "", 0, fmt.Errorf("port formatting err: %s", err)
	}

	return ip, port, nil
}

// Tracing helpers

func (f *Filter) startTraceSpan(xReqId, host string) {
	if f.spanIsActive() {
		return
	}
	ctx, span := telemetry.FilterTracer.Start(context.Background(), "http.server.request", trace.WithSpanKind(trace.SpanKindServer))
	f.span = span
	f.spanCtx = ctx
	f.recordOutcome(wafOutcomeProcessing)
	attrs := []attribute.KeyValue{
		attribute.String("http.host", host),
		attribute.String("coraza.metadata.cluster_name", f.Metadata.ClusterName),
		attribute.String("coraza.metadata.virtual_host_name", f.Metadata.VirtualHostName),
		attribute.String("coraza.metadata.route_name", f.Metadata.RouteName),
		attribute.String("coraza.metadata.filter_chain_name", f.Metadata.FilterChainName),
	}
	for key, value := range f.Metadata.TraceRouteAttributes {
		attrs = append(attrs, attribute.String(key, value))
	}
	if xReqId != "" {
		attrs = append(attrs, attribute.String("http.request.id", xReqId))
	}
	f.span.SetAttributes(attrs...)
	f.span.AddEvent("coraza.initialization")
}

func (f *Filter) spanIsActive() bool {
	return f.span != nil && f.span.SpanContext().IsValid()
}

func (f *Filter) spanAddAttributes(attrs ...attribute.KeyValue) {
	if !f.spanIsActive() {
		return
	}
	f.span.SetAttributes(attrs...)
}

func (f *Filter) spanAddEvent(name string, options ...trace.EventOption) {
	if !f.spanIsActive() {
		return
	}
	f.span.AddEvent(name, options...)
}

func (f *Filter) startChildSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if !f.spanIsActive() {
		return ctx, nil
	}
	if len(opts) == 0 {
		opts = append(opts, trace.WithSpanKind(trace.SpanKindInternal))
	}
	ctx, span := telemetry.FilterTracer.Start(ctx, name, opts...)
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

func (f *Filter) recordOutcome(outcome string) {
	f.wafOutcome = outcome
	f.spanAddAttributes(attribute.String("coraza.outcome", outcome))
}

func (f *Filter) endSpanWithReason(reason api.DestroyReason) {
	if !f.spanIsActive() {
		return
	}
	if f.wafOutcome == "" || f.wafOutcome == wafOutcomeProcessing {
		f.recordOutcome(wafOutcomeAllowed)
	}
	f.spanAddAttributes(attribute.String("coraza.envoy.destroy_reason", fmt.Sprintf("%v", reason)))
	f.span.AddEvent("coraza.span_finished")
	f.span.End()
	f.span = nil
	f.spanCtx = nil
}

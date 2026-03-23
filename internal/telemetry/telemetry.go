// Copyright © 2025 Datum Technology, Inc.
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"log"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/contrib/propagators/autoprop"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Meter is the global OTel meter for the coraza filter.
var Meter = otel.Meter("coraza/envoy/filter")

// FilterTracer is the global OTel tracer for the coraza filter.
var FilterTracer = otel.Tracer("coraza/envoy/filter")

// SetupOpenTelemetry configures OTel tracing, metrics, and propagation.
func SetupOpenTelemetry(ctx context.Context) (shutdown func(context.Context) error, err error) {
	var shutdownFuncs []func(context.Context) error

	shutdown = func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// Configure Context Propagation to use the default W3C traceparent format
	otel.SetTextMapPropagator(autoprop.NewTextMapPropagator())

	// Configure Trace Export to send spans as OTLP
	texporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		err = errors.Join(err, shutdown(ctx))
		return
	}
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("coraza-envoy-filter"),
		),
	)
	if err != nil {
		err = errors.Join(err, shutdown(ctx))
		return
	}
	tp := trace.NewTracerProvider(
		trace.WithBatcher(texporter),
		trace.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, tp.Shutdown)
	otel.SetTracerProvider(tp)

	// Configure Metric Export to send metrics as OTLP
	mreader, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		err = errors.Join(err, shutdown(ctx))
		return
	}
	mp := metric.NewMeterProvider(
		metric.WithReader(mreader),
		metric.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, mp.Shutdown)
	otel.SetMeterProvider(mp)

	// Start Go runtime metrics
	if err := otelruntime.Start(
		otelruntime.WithMeterProvider(mp),
		otelruntime.WithMinimumReadMemStatsInterval(10*time.Second),
	); err != nil {
		log.Fatal(err)
	}

	return shutdown, nil
}

package main

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type wafCacheMetrics struct {
	ctx           context.Context
	cacheHit      metric.Int64Counter
	cacheMiss     metric.Int64Counter
	buildAttempts metric.Int64Counter
	buildDuration metric.Float64Histogram
	entryGauge    metric.Int64ObservableGauge
}

func newWafCacheMetrics(m metric.Meter, entryGaugeCallback metric.Int64Callback) *wafCacheMetrics {
	cacheHit, err := m.Int64Counter("cache.hits")
	if err != nil {
		panic(err)
	}

	cacheMiss, err := m.Int64Counter("cache.misses")
	if err != nil {
		panic(err)
	}

	buildAttempts, err := m.Int64Counter("cache.builds")
	if err != nil {
		panic(err)
	}

	buildDuration, err := m.Float64Histogram("cache.build.duration")
	if err != nil {
		panic(err)
	}

	entryGauge, err := m.Int64ObservableGauge("cache.entries", metric.WithInt64Callback(entryGaugeCallback))
	if err != nil {
		panic(err)
	}

	return &wafCacheMetrics{
		ctx:           context.Background(),
		cacheHit:      cacheHit,
		cacheMiss:     cacheMiss,
		buildAttempts: buildAttempts,
		buildDuration: buildDuration,
		entryGauge:    entryGauge,
	}
}

func (m *wafCacheMetrics) recordHit() {
	m.cacheHit.Add(m.ctx, 1)
}

func (m *wafCacheMetrics) recordMiss() {
	m.cacheMiss.Add(m.ctx, 1)
}

func (m *wafCacheMetrics) recordBuild(result string, duration time.Duration) {
	opts := metric.WithAttributes(attribute.String("result", result))
	m.buildAttempts.Add(m.ctx, 1, opts)
	m.buildDuration.Record(m.ctx, duration.Seconds(), opts)
}

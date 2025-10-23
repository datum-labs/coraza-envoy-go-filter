package main

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type wafCacheMetrics struct {
	ctx                  context.Context
	cacheHit             metric.Int64Counter
	cacheMiss            metric.Int64Counter
	buildAttempts        metric.Int64Counter
	buildLatency         metric.Float64Histogram
	retainCalls          metric.Int64Counter
	entryGauge           metric.Int64UpDownCounter
	evictionCalls        metric.Int64Counter
	singleflightSharings metric.Int64Counter
}

func newWafCacheMetrics(m metric.Meter) *wafCacheMetrics {
	cacheHit, err := m.Int64Counter("waf_cache_hit_total")
	if err != nil {
		panic(err)
	}

	cacheMiss, err := m.Int64Counter("waf_cache_miss_total")
	if err != nil {
		panic(err)
	}

	buildAttempts, err := m.Int64Counter("waf_cache_build_total")
	if err != nil {
		panic(err)
	}

	buildLatency, err := m.Float64Histogram("waf_cache_build_duration_seconds")
	if err != nil {
		panic(err)
	}

	retainCalls, err := m.Int64Counter("waf_cache_retain_total")
	if err != nil {
		panic(err)
	}

	entryGauge, err := m.Int64UpDownCounter("waf_cache_entries")
	if err != nil {
		panic(err)
	}

	evictionCalls, err := m.Int64Counter("waf_cache_eviction_total")
	if err != nil {
		panic(err)
	}

	singleflightSharings, err := m.Int64Counter("waf_cache_singleflight_shared_total")
	if err != nil {
		panic(err)
	}

	return &wafCacheMetrics{
		ctx:                  context.Background(),
		cacheHit:             cacheHit,
		cacheMiss:            cacheMiss,
		buildAttempts:        buildAttempts,
		buildLatency:         buildLatency,
		retainCalls:          retainCalls,
		entryGauge:           entryGauge,
		evictionCalls:        evictionCalls,
		singleflightSharings: singleflightSharings,
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
	m.buildLatency.Record(m.ctx, duration.Seconds(), opts)
}

func (m *wafCacheMetrics) recordRetain(isNew bool) {
	opts := metric.WithAttributes(attribute.Bool("new_entry", isNew))
	m.retainCalls.Add(m.ctx, 1, opts)
	if isNew {
		m.entryGauge.Add(m.ctx, 1)
	}
}

func (m *wafCacheMetrics) recordEviction(reason string) {
	m.evictionCalls.Add(m.ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	m.entryGauge.Add(m.ctx, -1)
}

func (m *wafCacheMetrics) recordSingleflightShared() {
	m.singleflightSharings.Add(m.ctx, 1)
}

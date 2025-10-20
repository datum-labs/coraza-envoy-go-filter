package main

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/karlseguin/ccache/v3"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/singleflight"
)

// wafCacheStore caches built WAF instances keyed by the configuration hash. It
// wraps ccache with singleflight to dedupe concurrent builds and records
// TTL-based metrics so frequently reused configurations avoid rebuilds.
// Items will not actually be evicted until the cache store reaches its max
// size.
type wafCacheStore struct {
	cache *ccache.Cache[*wafCacheEntry]

	group singleflight.Group

	ttl time.Duration

	metrics *wafCacheMetrics
}

type wafCacheEntry struct {
	waf coraza.WAF
	// error encountered during WAF build, if any
	buildErr error
}

func newWafCacheStore() *wafCacheStore {
	ttl := 5 * time.Minute
	// Get TTL from environment variable or use default.
	if v := os.Getenv("WAF_CACHE_TTL_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ttl = d
		} else {
			api.LogErrorf("invalid WAF_CACHE_TTL_DURATION value %s, using default %s", v, ttl.String())
		}
	}

	maxCacheSize := int64(1000)
	// Get max cache size from environment variable or use default.
	if v := os.Getenv("WAF_CACHE_MAX_SIZE"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			maxCacheSize = i
		} else {
			api.LogErrorf("invalid WAF_CACHE_MAX_SIZE value %s, using default %d", v, maxCacheSize)
		}
	}

	cache := ccache.New(ccache.Configure[*wafCacheEntry]().MaxSize(maxCacheSize))
	return &wafCacheStore{
		cache: cache,
		ttl:   ttl,
		metrics: newWafCacheMetrics(meter, func(ctx context.Context, o metric.Int64Observer) error {
			o.Observe(cache.GetSize())
			return nil
		}),
	}
}

func (w *wafCacheStore) Get(hash string, wafInitFunc func() (coraza.WAF, error)) (coraza.WAF, error) {
	entry := w.cache.Get(hash)
	if entry == nil {
		w.metrics.recordMiss()
		v, _, _ := w.group.Do(hash, func() (any, error) {
			api.LogDebugf("WAF cache miss for hash %s, building new WAF instance", hash)
			start := time.Now()
			waf, err := wafInitFunc()
			cacheEntry := &wafCacheEntry{
				waf:      waf,
				buildErr: err,
			}

			if err == nil {
				w.metrics.recordBuild("success", time.Since(start))
			} else {
				w.metrics.recordBuild("error", time.Since(start))
			}
			api.LogDebugf("WAF instance build for hash %s took %s", hash, time.Since(start).String())

			w.cache.Set(hash, cacheEntry, w.ttl)
			return cacheEntry, nil
		})
		cacheEntry := v.(*wafCacheEntry)
		return cacheEntry.waf, cacheEntry.buildErr
	} else {
		api.LogDebugf("WAF cache hit for hash %s", hash)
		w.metrics.recordHit()

		if time.Until(entry.Expires()) < w.ttl/10 {
			entry.Extend(w.ttl)
		}
	}

	return entry.Value().waf, entry.Value().buildErr
}

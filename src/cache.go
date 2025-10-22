package main

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"golang.org/x/sync/singleflight"
)

// wafCacheStore keeps WAF instances keyed by directive hash and manages ref
// counts with TTL eviction. TTL eviction is desirable as Envoy will create and
// destroy listener/route configurations on any update to the Envoy config. We
// want to avoid recreating WAF instances unnecessarily.
type wafCacheStore struct {
	mu sync.RWMutex

	// hashed directives -> cached WAF metadata
	entries map[[sha256.Size]byte]*wafCacheEntry

	group singleflight.Group

	// duration to keep zero-ref entries alive
	ttl time.Duration

	metrics *wafCacheMetrics
}

func newWafCacheStore(ttl time.Duration) *wafCacheStore {
	return &wafCacheStore{
		entries: make(map[[sha256.Size]byte]*wafCacheEntry),
		ttl:     ttl,
		metrics: newWafCacheMetrics(meter),
	}
}

// retain increments the reference count for the directive hash, creating an entry if needed.
func (c *wafCacheStore) retain(hash [sha256.Size]byte) {
	c.mu.Lock()
	if entry, ok := c.entries[hash]; ok {
		entry.refCount++
		entry.zeroAt = time.Time{}
		c.metrics.recordRetain(false)
		c.mu.Unlock()
		return
	}
	entry := &wafCacheEntry{
		refCount: 1,
	}
	c.entries[hash] = entry
	c.metrics.recordRetain(true)
	c.mu.Unlock()
}

// ensure returns an existing WAF or builds it if absent without altering the reference count.
func (c *wafCacheStore) ensure(hash [sha256.Size]byte, build func() (coraza.WAF, error)) (coraza.WAF, error) {
	c.mu.RLock()
	entry, ok := c.entries[hash]
	if !ok {
		panic("ensure called without prior retain")
	}

	if entry.waf != nil && entry.buildErr != nil {
		panic("wafCacheStore invariant violated: both waf and buildErr set")
	}

	if entry.waf != nil {
		c.metrics.recordHit()
		waf := entry.waf
		c.mu.RUnlock()
		return waf, nil
	}

	if entry.buildErr != nil {
		err := entry.buildErr
		c.mu.RUnlock()
		return nil, err
	}

	c.metrics.recordMiss()

	// Release main lock before entering singleflight to avoid blocking other operations.
	c.mu.RUnlock()

	waf, err, shared := c.group.Do(string(hash[:]), func() (interface{}, error) {
		// Optimistic check if another goroutine created the WAF while we waited for
		// the lock.
		c.mu.Lock()
		entry, ok = c.entries[hash]
		if !ok {
			panic("ensure called without prior retain")
		}

		if entry.waf != nil && entry.buildErr != nil {
			panic("wafCacheStore invariant violated: both waf and buildErr set")
		}

		if entry.waf != nil {
			waf := entry.waf
			c.mu.Unlock()
			return waf, nil
		}

		if entry.buildErr != nil {
			err := entry.buildErr
			c.mu.Unlock()
			return nil, err
		}

		// Release the lock while building the WAF.
		c.mu.Unlock()

		start := time.Now()
		waf, err := build()
		if err != nil {
			c.mu.Lock()
			entry.buildErr = err
			c.mu.Unlock()
			c.metrics.recordBuild("error", time.Since(start))
			return nil, err
		}

		c.mu.Lock()
		entry.waf = waf
		entry.buildErr = nil
		entry.zeroAt = time.Time{}
		c.mu.Unlock()

		c.metrics.recordBuild("success", time.Since(start))

		return waf, nil
	})
	if err != nil {
		return nil, err
	}
	if shared {
		c.metrics.recordSingleflightShared()
	}
	return waf.(coraza.WAF), nil
}

// release decrements the ref count and schedules eviction once the entry remains unused for ttl.
func (c *wafCacheStore) release(hash [sha256.Size]byte) {
	c.mu.Lock()
	entry, ok := c.entries[hash]
	if !ok {
		// Nothing to do
		c.mu.Unlock()
		return
	}

	if entry.refCount <= 0 {
		panic("wafCacheStore.release: non-positive refCount")
	}
	entry.refCount--
	if entry.refCount == 0 {
		zeroAt := time.Now()
		entry.zeroAt = zeroAt
		c.mu.Unlock()
		c.scheduleEviction(hash, zeroAt)
		return
	}
	c.mu.Unlock()
}

func (c *wafCacheStore) scheduleEviction(hash [sha256.Size]byte, zeroAt time.Time) {
	time.AfterFunc(c.ttl, func() {
		c.evictIfExpired(hash, zeroAt)
	})
}

func (c *wafCacheStore) evictIfExpired(hash [sha256.Size]byte, zeroAt time.Time) {
	c.mu.Lock()
	entry, ok := c.entries[hash]
	if !ok {
		c.mu.Unlock()
		return
	}
	if entry.refCount > 0 || !entry.zeroAt.Equal(zeroAt) {
		c.mu.Unlock()
		return
	}
	delete(c.entries, hash)
	c.mu.Unlock()

	c.metrics.recordEviction("ttl_expired")
}

package pip

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// DecisionCache provides temporal-bounded caching for PDP decisions.
// RFC-005 §6.3: PEPs MUST NOT cache a decision beyond the earliest of:
// - The ttl value from the PDP response
// - The governing Envelope's expires_at (N/A in badge-only mode)
// - The Badge's expiration (exp claim)
type DecisionCache interface {
	// Get retrieves a cached decision. Returns nil, false on miss or expiry.
	Get(key string) (*DecisionResponse, bool)

	// Put stores a decision with a maximum TTL.
	// The cache MUST NOT serve this entry after maxTTL elapses.
	Put(key string, resp *DecisionResponse, maxTTL time.Duration)
}

// CacheKeyComponents builds a deterministic cache key from PIP request fields.
// Key includes: subject.did + subject.badge_jti + action.operation + resource.identifier.
func CacheKeyComponents(did, badgeJTI, operation, resourceID string) string {
	h := sha256.New()
	// Use a separator that cannot appear in DIDs or operation strings
	for _, s := range []string{did, badgeJTI, operation, resourceID} {
		fmt.Fprintf(h, "%s\x00", s)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// cacheEntry holds a cached decision with its expiration.
type cacheEntry struct {
	resp      *DecisionResponse
	expiresAt time.Time
}

// InMemoryCache is a simple in-memory DecisionCache.
// Suitable for single-instance deployments. For multi-instance, use a shared cache.
type InMemoryCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry

	// cacheDeny controls whether DENY decisions are cached.
	// Default false per RFC-005 §6.3 last paragraph.
	cacheDeny bool

	// nowFunc is injectable for testing.
	nowFunc func() time.Time
}

// InMemoryCacheOption configures an InMemoryCache.
type InMemoryCacheOption func(*InMemoryCache)

// WithCacheDeny enables caching of DENY decisions.
// WARNING: Caching DENY can cause persistent blocks after PDP recovery ("deny storm").
func WithCacheDeny(enabled bool) InMemoryCacheOption {
	return func(c *InMemoryCache) {
		c.cacheDeny = enabled
	}
}

// NewInMemoryCache creates a new in-memory decision cache.
func NewInMemoryCache(opts ...InMemoryCacheOption) *InMemoryCache {
	c := &InMemoryCache{
		entries: make(map[string]cacheEntry),
		nowFunc: time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Get retrieves a cached decision if it exists and has not expired.
// Expired entries are evicted on read to prevent unbounded memory growth.
func (c *InMemoryCache) Get(key string) (*DecisionResponse, bool) {
	now := c.nowFunc()

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if now.After(entry.expiresAt) {
		// Upgrade to write lock and evict the expired entry.
		c.mu.Lock()
		defer c.mu.Unlock()
		// Re-check under write lock in case it was updated concurrently.
		entry, ok = c.entries[key]
		if ok && now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
		return nil, false
	}

	return entry.resp, true
}

// Put stores a decision with a bounded TTL.
// Skips DENY decisions unless cacheDeny is enabled.
// Skips if maxTTL is zero or negative (badge already expired).
func (c *InMemoryCache) Put(key string, resp *DecisionResponse, maxTTL time.Duration) {
	if resp == nil {
		return
	}
	if !c.cacheDeny && resp.Decision == DecisionDeny {
		return
	}
	if maxTTL <= 0 {
		return
	}

	// Compute effective TTL: min(PDP response TTL, maxTTL from badge expiry)
	effectiveTTL := maxTTL
	if resp.TTL != nil && *resp.TTL > 0 {
		pdpTTL := time.Duration(*resp.TTL) * time.Second
		if pdpTTL < effectiveTTL {
			effectiveTTL = pdpTTL
		}
	}

	if effectiveTTL <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = cacheEntry{
		resp:      resp,
		expiresAt: c.nowFunc().Add(effectiveTTL),
	}
}

// Package pop provides shared Proof of Possession cryptographic primitives.
// This file implements session caching for verified PoP results.
//
// Session caching avoids re-verifying on every request within a session.
// Per team guidance, session definitions:
// - HTTP: per connection or per TTL window (configurable)
// - MCP stdio: per process lifetime or per initialize session
//
// Cache invalidation occurs on:
// - Badge expiry
// - TTL expiry (configurable, default: sync with badge TTL)
// - Explicit invalidation (key rotation, trust level change)
package pop

import (
	"sync"
	"time"
)

// SessionCache provides thread-safe caching of PoP verification results
type SessionCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	config  *CacheConfig
}

// CacheConfig configures session cache behavior
type CacheConfig struct {
	// DefaultTTL is the default cache entry lifetime
	// Should generally match badge TTL (default: 5 minutes)
	DefaultTTL time.Duration

	// MaxEntries limits cache size (0 = unlimited)
	MaxEntries int

	// CleanupInterval is how often to purge expired entries (0 = no background cleanup)
	CleanupInterval time.Duration
}

// DefaultCacheConfig returns sensible defaults
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		DefaultTTL:      5 * time.Minute,
		MaxEntries:      1000,
		CleanupInterval: time.Minute,
	}
}

// CacheEntry represents a cached verification result
type CacheEntry struct {
	// SubjectDID is the verified DID
	SubjectDID string

	// TrustLevelStr from verified badge (string per RFC-002 §5)
	TrustLevelStr string

	// BadgeJTI for correlation
	BadgeJTI string

	// BadgeExpiresAt is when the badge expires
	BadgeExpiresAt time.Time

	// VerifiedAt is when PoP was verified
	VerifiedAt time.Time

	// ExpiresAt is when this cache entry expires
	ExpiresAt time.Time

	// SessionID for MCP session correlation (optional)
	SessionID string
}

// NewSessionCache creates a new session cache
func NewSessionCache(config *CacheConfig) *SessionCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	cache := &SessionCache{
		entries: make(map[string]*CacheEntry),
		config:  config,
	}

	// Start background cleanup if configured
	if config.CleanupInterval > 0 {
		go cache.cleanupLoop()
	}

	return cache
}

// Store caches a verification result
// Key is typically the server DID
func (c *SessionCache) Store(key string, entry *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Set expiry if not already set
	if entry.ExpiresAt.IsZero() {
		// Use badge expiry if sooner than default TTL
		expiresAt := time.Now().Add(c.config.DefaultTTL)
		if !entry.BadgeExpiresAt.IsZero() && entry.BadgeExpiresAt.Before(expiresAt) {
			expiresAt = entry.BadgeExpiresAt
		}
		entry.ExpiresAt = expiresAt
	}

	// Enforce max entries (simple LRU: remove oldest)
	if c.config.MaxEntries > 0 && len(c.entries) >= c.config.MaxEntries {
		var oldestKey string
		var oldestTime time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.VerifiedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = e.VerifiedAt
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}

	c.entries[key] = entry
}

// Get retrieves a cached entry if valid
// Returns nil if not found or expired
func (c *SessionCache) Get(key string) *CacheEntry {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil
	}

	// Check expiry
	if time.Now().After(entry.ExpiresAt) {
		c.Delete(key)
		return nil
	}

	// Also invalidate if badge expired
	if !entry.BadgeExpiresAt.IsZero() && time.Now().After(entry.BadgeExpiresAt) {
		c.Delete(key)
		return nil
	}

	return entry
}

// Delete removes a cached entry
func (c *SessionCache) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// InvalidateBySession removes all entries for a session
func (c *SessionCache) InvalidateBySession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if entry.SessionID == sessionID {
			delete(c.entries, key)
		}
	}
}

// InvalidateByTrustLevel removes entries below a trust level
// Use when trust requirements increase mid-session
// minLevelStr should be "0", "1", "2", "3", or "4"
func (c *SessionCache) InvalidateByTrustLevel(minLevelStr string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		// String comparison works for single-digit levels "0"-"4"
		if entry.TrustLevelStr < minLevelStr {
			delete(c.entries, key)
		}
	}
}

// Clear removes all entries
func (c *SessionCache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*CacheEntry)
	c.mu.Unlock()
}

// Size returns the number of cached entries
func (c *SessionCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// cleanupLoop periodically removes expired entries
func (c *SessionCache) cleanupLoop() {
	ticker := time.NewTicker(c.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup removes all expired entries
func (c *SessionCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		} else if !entry.BadgeExpiresAt.IsZero() && now.After(entry.BadgeExpiresAt) {
			delete(c.entries, key)
		}
	}
}

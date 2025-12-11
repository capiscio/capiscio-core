// Package revocation provides a local cache for badge revocations.
// This enables offline and semi-connected verification modes.
// See RFC-002 §7.4 Cache Staleness Guidance.
package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Common errors returned by this package.
var (
	ErrCacheNotFound = errors.New("revocation cache not found")
	ErrCacheCorrupt  = errors.New("revocation cache is corrupt")
)

// DefaultStaleThreshold is the default time after which cache is considered stale.
// Per RFC-002 §7.4, default is 5 minutes.
const DefaultStaleThreshold = 5 * time.Minute

// Cache is the interface for a revocation cache.
type Cache interface {
	// IsRevoked checks if a badge jti is in the revocation cache.
	IsRevoked(jti string) bool

	// Add adds a revocation to the cache.
	Add(jti string, revokedAt time.Time) error

	// Sync updates the cache with new revocations.
	Sync(revocations []Revocation) error

	// LastSynced returns when the cache was last synced.
	LastSynced() time.Time

	// IsStale returns true if the cache is older than the threshold.
	IsStale(threshold time.Duration) bool

	// Clear clears all revocations from the cache.
	Clear() error
}

// Revocation represents a single revocation entry.
type Revocation struct {
	// JTI is the revoked badge ID.
	JTI string `json:"jti"`

	// RevokedAt is when the badge was revoked.
	RevokedAt time.Time `json:"revokedAt"`

	// Reason is the optional revocation reason.
	Reason string `json:"reason,omitempty"`
}

// cacheData is the serialized cache format.
type cacheData struct {
	SyncedAt    time.Time    `json:"syncedAt"`
	Revocations []Revocation `json:"revocations"`
}

// FileCache implements Cache using a JSON file.
type FileCache struct {
	path string
	mu   sync.RWMutex

	// In-memory cache
	data     *cacheData
	jtiIndex map[string]bool
}

// DefaultCacheDir returns the default revocation cache directory.
func DefaultCacheDir() string {
	if envPath := os.Getenv("CAPISCIO_CACHE_PATH"); envPath != "" {
		return envPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".capiscio/cache"
	}
	return filepath.Join(home, ".capiscio", "cache")
}

// NewFileCache creates a new file-based revocation cache.
// If path is empty, uses default location.
func NewFileCache(path string) (*FileCache, error) {
	if path == "" {
		path = filepath.Join(DefaultCacheDir(), "revocations.json")
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &FileCache{
		path:     path,
		jtiIndex: make(map[string]bool),
	}

	// Try to load existing cache
	if err := cache.load(); err != nil && !os.IsNotExist(err) {
		// Log warning but continue with empty cache
		cache.data = &cacheData{}
	}

	return cache, nil
}

// IsRevoked checks if a badge jti is in the revocation cache.
func (c *FileCache) IsRevoked(jti string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.jtiIndex[jti]
}

// Add adds a single revocation to the cache.
func (c *FileCache) Add(jti string, revokedAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data == nil {
		c.data = &cacheData{}
	}

	// Check if already exists
	if c.jtiIndex[jti] {
		return nil
	}

	c.data.Revocations = append(c.data.Revocations, Revocation{
		JTI:       jti,
		RevokedAt: revokedAt,
	})
	c.jtiIndex[jti] = true
	c.data.SyncedAt = time.Now()

	return c.save()
}

// Sync updates the cache with new revocations from the registry.
func (c *FileCache) Sync(revocations []Revocation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.data == nil {
		c.data = &cacheData{}
	}

	// Add new revocations
	for _, rev := range revocations {
		if !c.jtiIndex[rev.JTI] {
			c.data.Revocations = append(c.data.Revocations, rev)
			c.jtiIndex[rev.JTI] = true
		}
	}

	c.data.SyncedAt = time.Now()
	return c.save()
}

// LastSynced returns when the cache was last synced.
func (c *FileCache) LastSynced() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil {
		return time.Time{}
	}
	return c.data.SyncedAt
}

// IsStale returns true if the cache is older than the threshold.
// Per RFC-002, default threshold is 5 minutes.
func (c *FileCache) IsStale(threshold time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil || c.data.SyncedAt.IsZero() {
		return true
	}

	return time.Since(c.data.SyncedAt) > threshold
}

// Clear removes all revocations from the cache.
func (c *FileCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = &cacheData{}
	c.jtiIndex = make(map[string]bool)

	// Remove the file if it exists
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	return nil
}

// Count returns the number of revocations in the cache.
func (c *FileCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil {
		return 0
	}
	return len(c.data.Revocations)
}

// load reads the cache from disk.
func (c *FileCache) load() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}

	var cached cacheData
	if err := json.Unmarshal(data, &cached); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheCorrupt, err)
	}

	c.data = &cached

	// Build index
	c.jtiIndex = make(map[string]bool, len(cached.Revocations))
	for _, rev := range cached.Revocations {
		c.jtiIndex[rev.JTI] = true
	}

	return nil
}

// save writes the cache to disk.
func (c *FileCache) save() error {
	if c.data == nil {
		return nil
	}

	data, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	if err := os.WriteFile(c.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}

	return nil
}

// MemoryCache is an in-memory only cache for testing.
type MemoryCache struct {
	mu          sync.RWMutex
	revocations map[string]Revocation
	syncedAt    time.Time
}

// NewMemoryCache creates a new in-memory revocation cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		revocations: make(map[string]Revocation),
	}
}

// IsRevoked checks if a badge JTI has been revoked.
func (c *MemoryCache) IsRevoked(jti string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.revocations[jti]
	return ok
}

// Add adds a revoked badge to the cache.
func (c *MemoryCache) Add(jti string, revokedAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revocations[jti] = Revocation{JTI: jti, RevokedAt: revokedAt}
	c.syncedAt = time.Now()
	return nil
}

// Sync synchronizes the cache with a list of revocations.
func (c *MemoryCache) Sync(revocations []Revocation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rev := range revocations {
		c.revocations[rev.JTI] = rev
	}
	c.syncedAt = time.Now()
	return nil
}

// LastSynced returns the time of the last cache sync.
func (c *MemoryCache) LastSynced() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.syncedAt
}

// IsStale returns true if the cache hasn't been synced within the threshold.
func (c *MemoryCache) IsStale(threshold time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.syncedAt.IsZero() {
		return true
	}
	return time.Since(c.syncedAt) > threshold
}

func (c *MemoryCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revocations = make(map[string]Revocation)
	c.syncedAt = time.Time{}
	return nil
}

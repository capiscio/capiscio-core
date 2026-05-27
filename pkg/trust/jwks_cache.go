// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package trust

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSCache provides tiered caching of issuer JWKS material.
// Level 1: In-memory cache (hot path, sub-microsecond lookup)
// Level 2: Filesystem cache (warm path, persists across restarts)
//
// The cache supports soft/hard TTL semantics per RFC-001 §2.3:
// - SoftTTL: Target refresh interval. After SoftTTL, background refresh triggers.
// - HardTTL: Maximum staleness. After HardTTL, the configured StalePolicy applies.
type JWKSCache struct {
	// Configuration
	dir      string
	policy   FreshnessPolicy
	fetcher  JWKSFetcher // Optional: for background refresh
	logger   Logger

	// In-memory cache (L1)
	mu      sync.RWMutex
	entries map[string]*jwksCacheEntry

	// Background refresh
	refreshMu      sync.Mutex
	refreshPending map[string]bool
	stopRefresh    chan struct{}
	wg             sync.WaitGroup
}

// jwksCacheEntry holds cached JWKS for a single issuer.
type jwksCacheEntry struct {
	IssuerDID string
	Keys      []jose.JSONWebKey
	FetchedAt time.Time
	ExpiresAt time.Time
	SourceURL string
}

// JWKSFetcher defines the interface for fetching JWKS from a remote source.
// This is used for background refresh only — not in the verification critical path.
type JWKSFetcher interface {
	// FetchJWKS retrieves JWKS for an issuer. Called during background refresh only.
	FetchJWKS(ctx context.Context, issuerDID string) (*jose.JSONWebKeySet, error)
}

// Logger is a minimal logging interface.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// noopLogger is a no-op logger implementation.
type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}

// JWKSCacheOption configures a JWKSCache.
type JWKSCacheOption func(*JWKSCache)

// WithJWKSCacheDir sets the filesystem cache directory.
func WithJWKSCacheDir(dir string) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.dir = dir
	}
}

// WithFreshnessPolicy sets the TTL and staleness policy.
func WithFreshnessPolicy(p FreshnessPolicy) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.policy = p
	}
}

// WithJWKSFetcher sets the fetcher for background refresh.
func WithJWKSFetcher(f JWKSFetcher) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.fetcher = f
	}
}

// WithLogger sets the logger.
func WithLogger(l Logger) JWKSCacheOption {
	return func(c *JWKSCache) {
		c.logger = l
	}
}

// NewJWKSCache creates a new JWKS cache.
func NewJWKSCache(opts ...JWKSCacheOption) (*JWKSCache, error) {
	c := &JWKSCache{
		policy:         DefaultFreshnessPolicy(),
		logger:         noopLogger{},
		entries:        make(map[string]*jwksCacheEntry),
		refreshPending: make(map[string]bool),
		stopRefresh:    make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Ensure cache directory exists if specified
	if c.dir != "" {
		if err := os.MkdirAll(c.dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create JWKS cache directory: %w", err)
		}
	}

	return c, nil
}

// Get retrieves the public key for an issuer by kid.
// This is the hot path — must be fast and local-only.
// Returns (key, freshness, error).
func (c *JWKSCache) Get(issuerDID, kid string) (crypto.PublicKey, FreshnessState, error) {
	c.mu.RLock()
	entry, ok := c.entries[issuerDID]
	c.mu.RUnlock()

	// L1 cache miss — try L2 (filesystem)
	if !ok {
		var err error
		entry, err = c.loadFromDisk(issuerDID)
		if err != nil {
			return nil, FreshnessStateExpired, ErrIssuerNotFound
		}

		// Promote to L1
		c.mu.Lock()
		c.entries[issuerDID] = entry
		c.mu.Unlock()
	}

	// Evaluate freshness
	now := time.Now()
	freshness := c.evaluateFreshness(entry, now)

	// Handle staleness policy
	switch freshness {
	case FreshnessStateExpired:
		switch c.policy.StalePolicy {
		case StalePolicyFailClosed:
			return nil, FreshnessStateExpired, &StaleKeyMaterialError{
				IssuerDID: issuerDID,
				StaleSince: entry.ExpiresAt,
			}
		case StalePolicyDegraded:
			c.logger.Warn("using degraded key material",
				"issuer", issuerDID,
				"stale_since", entry.ExpiresAt)
			freshness = FreshnessStateDegraded
		case StalePolicyWarnAndAllow:
			c.logger.Warn("using stale key material (dev mode)",
				"issuer", issuerDID,
				"stale_since", entry.ExpiresAt)
		}
	case FreshnessStateStale:
		// Trigger background refresh
		c.triggerBackgroundRefresh(issuerDID)
	}

	// Find key by kid
	for _, jwk := range entry.Keys {
		if jwk.KeyID == kid {
			return jwk.Key, freshness, nil
		}
	}

	// If kid not specified, return first key
	if kid == "" && len(entry.Keys) > 0 {
		return entry.Keys[0].Key, freshness, nil
	}

	return nil, freshness, ErrKeyNotFound
}

// GetAllKeys retrieves all keys for an issuer.
func (c *JWKSCache) GetAllKeys(issuerDID string) ([]jose.JSONWebKey, FreshnessState, error) {
	c.mu.RLock()
	entry, ok := c.entries[issuerDID]
	c.mu.RUnlock()

	if !ok {
		var err error
		entry, err = c.loadFromDisk(issuerDID)
		if err != nil {
			return nil, FreshnessStateExpired, ErrIssuerNotFound
		}
		c.mu.Lock()
		c.entries[issuerDID] = entry
		c.mu.Unlock()
	}

	freshness := c.evaluateFreshness(entry, time.Now())
	return entry.Keys, freshness, nil
}

// Put stores JWKS for an issuer. Used during bootstrap and refresh.
func (c *JWKSCache) Put(issuerDID string, jwks *jose.JSONWebKeySet, sourceURL string) error {
	now := time.Now()
	entry := &jwksCacheEntry{
		IssuerDID: issuerDID,
		Keys:      jwks.Keys,
		FetchedAt: now,
		ExpiresAt: now.Add(c.policy.HardTTL),
		SourceURL: sourceURL,
	}

	// Write to L1 (memory)
	c.mu.Lock()
	c.entries[issuerDID] = entry
	c.mu.Unlock()

	// Write to L2 (disk)
	if c.dir != "" {
		if err := c.saveToDisk(issuerDID, entry); err != nil {
			c.logger.Warn("failed to persist JWKS to disk",
				"issuer", issuerDID,
				"error", err)
		}
	}

	return nil
}

// LoadFromBundle imports trust material from an exported bundle.
// This is used during bootstrap to pre-populate the cache.
func (c *JWKSCache) LoadFromBundle(bundle *TrustMaterial) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for issuerDID, issuerKeys := range bundle.JWKS {
		// Convert to JWK format
		var jwks []jose.JSONWebKey
		for _, pk := range issuerKeys.Keys {
			jwk := jose.JSONWebKey{Key: pk}
			jwks = append(jwks, jwk)
		}

		c.entries[issuerDID] = &jwksCacheEntry{
			IssuerDID: issuerDID,
			Keys:      jwks,
			FetchedAt: issuerKeys.FetchedAt,
			ExpiresAt: issuerKeys.ExpiresAt,
			SourceURL: issuerKeys.SourceURL,
		}
	}

	c.logger.Info("loaded trust bundle",
		"issuers", len(bundle.JWKS),
		"version", bundle.Metadata.Version)

	return nil
}

// Export creates a trust bundle from the current cache state.
func (c *JWKSCache) Export() *TrustMaterial {
	c.mu.RLock()
	defer c.mu.RUnlock()

	bundle := &TrustMaterial{
		JWKS: make(map[string]*IssuerKeys),
		Metadata: MaterialMetadata{
			CreatedAt:   time.Now(),
			LastRefresh: time.Now(),
		},
	}

	for issuerDID, entry := range c.entries {
		var keys []crypto.PublicKey
		for _, jwk := range entry.Keys {
			keys = append(keys, jwk.Key)
		}

		bundle.JWKS[issuerDID] = &IssuerKeys{
			IssuerDID: issuerDID,
			Keys:      keys,
			FetchedAt: entry.FetchedAt,
			ExpiresAt: entry.ExpiresAt,
			SourceURL: entry.SourceURL,
		}
	}

	return bundle
}

// Close stops background refresh goroutines.
func (c *JWKSCache) Close() error {
	close(c.stopRefresh)
	c.wg.Wait()
	return nil
}

// evaluateFreshness determines the freshness state of an entry.
func (c *JWKSCache) evaluateFreshness(entry *jwksCacheEntry, now time.Time) FreshnessState {
	age := now.Sub(entry.FetchedAt)

	if age <= c.policy.SoftTTL {
		return FreshnessStateFresh
	}

	if age <= c.policy.HardTTL {
		return FreshnessStateStale
	}

	if age <= c.policy.HardTTL+c.policy.GracePeriod {
		return FreshnessStateDegraded
	}

	return FreshnessStateExpired
}

// triggerBackgroundRefresh starts an async refresh if not already pending.
func (c *JWKSCache) triggerBackgroundRefresh(issuerDID string) {
	if c.fetcher == nil {
		return
	}

	c.refreshMu.Lock()
	if c.refreshPending[issuerDID] {
		c.refreshMu.Unlock()
		return
	}
	c.refreshPending[issuerDID] = true
	c.refreshMu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			c.refreshMu.Lock()
			delete(c.refreshPending, issuerDID)
			c.refreshMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		jwks, err := c.fetcher.FetchJWKS(ctx, issuerDID)
		if err != nil {
			c.logger.Warn("background JWKS refresh failed",
				"issuer", issuerDID,
				"error", err)
			return
		}

		if err := c.Put(issuerDID, jwks, ""); err != nil {
			c.logger.Warn("failed to update cache after refresh",
				"issuer", issuerDID,
				"error", err)
		}

		c.logger.Debug("background JWKS refresh completed",
			"issuer", issuerDID)
	}()
}

// loadFromDisk loads a cached entry from the filesystem.
func (c *JWKSCache) loadFromDisk(issuerDID string) (*jwksCacheEntry, error) {
	if c.dir == "" {
		return nil, ErrIssuerNotFound
	}

	path := c.cachePath(issuerDID)
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from cache dir + DID hash
	if err != nil {
		return nil, err
	}

	var entry jwksCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// saveToDisk persists a cache entry to the filesystem.
func (c *JWKSCache) saveToDisk(issuerDID string, entry *jwksCacheEntry) error {
	if c.dir == "" {
		return nil
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	path := c.cachePath(issuerDID)
	return os.WriteFile(path, data, 0600)
}

// cachePath returns the filesystem path for an issuer's cache file.
func (c *JWKSCache) cachePath(issuerDID string) string {
	safe := sanitizeFilename(issuerDID)
	return filepath.Join(c.dir, safe+".jwks.json")
}

// StaleKeyMaterialError indicates key material has exceeded HardTTL.
type StaleKeyMaterialError struct {
	IssuerDID  string
	StaleSince time.Time
}

func (e *StaleKeyMaterialError) Error() string {
	return fmt.Sprintf("key material for %s is stale (expired %s)", e.IssuerDID, e.StaleSince)
}

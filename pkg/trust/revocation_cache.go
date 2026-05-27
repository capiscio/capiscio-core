// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RevocationCache provides local caching of revocation status.
// Revocation data is synchronized asynchronously via delta sync,
// not per-verification — per RFC-001 §2.3.
//
// The cache supports:
// - Full sync: Download complete revocation list
// - Delta sync: Download only changes since last cursor
// - Local-only: Return cached status without network
type RevocationCache struct {
	// Configuration
	dir    string
	policy FreshnessPolicy
	syncer RevocationSyncer // Optional: for background sync
	logger Logger

	// In-memory cache
	mu       sync.RWMutex
	revoked  map[string]*RevocationEntry // Key: JTI
	metadata *revocationMetadata

	// Background sync
	syncMu      sync.Mutex
	syncPending bool
	stopSync    chan struct{}
	wg          sync.WaitGroup
}

// revocationMetadata tracks sync state.
type revocationMetadata struct {
	SyncedAt     time.Time `json:"synced_at"`
	Cursor       string    `json:"cursor"` // For delta sync
	IssuerDID    string    `json:"issuer_did"`
	TotalRevoked int       `json:"total_revoked"`
}

// RevocationSyncer defines the interface for syncing revocation data.
// This is called during background sync only — not in the verification critical path.
type RevocationSyncer interface {
	// SyncRevocations fetches revocation updates since the given cursor.
	// If cursor is empty, performs a full sync.
	// Returns (entries, nextCursor, error).
	SyncRevocations(ctx context.Context, issuerDID string, cursor string) ([]RevocationEntry, string, error)
}

// RevocationCacheOption configures a RevocationCache.
type RevocationCacheOption func(*RevocationCache)

// WithRevocationCacheDir sets the filesystem cache directory.
func WithRevocationCacheDir(dir string) RevocationCacheOption {
	return func(c *RevocationCache) {
		c.dir = dir
	}
}

// WithRevocationFreshnessPolicy sets the TTL policy.
func WithRevocationFreshnessPolicy(p FreshnessPolicy) RevocationCacheOption {
	return func(c *RevocationCache) {
		c.policy = p
	}
}

// WithRevocationSyncer sets the syncer for background updates.
func WithRevocationSyncer(s RevocationSyncer) RevocationCacheOption {
	return func(c *RevocationCache) {
		c.syncer = s
	}
}

// WithRevocationLogger sets the logger.
func WithRevocationLogger(l Logger) RevocationCacheOption {
	return func(c *RevocationCache) {
		c.logger = l
	}
}

// NewRevocationCache creates a new revocation cache.
func NewRevocationCache(opts ...RevocationCacheOption) (*RevocationCache, error) {
	c := &RevocationCache{
		policy:   DefaultFreshnessPolicy(),
		logger:   noopLogger{},
		revoked:  make(map[string]*RevocationEntry),
		metadata: &revocationMetadata{},
		stopSync: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Ensure cache directory exists if specified
	if c.dir != "" {
		if err := os.MkdirAll(c.dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create revocation cache directory: %w", err)
		}
	}

	return c, nil
}

// IsRevoked checks if a JTI is revoked. This is the hot path — local-only.
// Returns (isRevoked, freshness, error).
func (c *RevocationCache) IsRevoked(jti string) (bool, FreshnessState, error) {
	c.mu.RLock()
	entry, revoked := c.revoked[jti]
	metadata := c.metadata
	c.mu.RUnlock()

	// Evaluate freshness
	freshness := c.evaluateFreshness(metadata)

	// Trigger background sync if stale
	if freshness == FreshnessStateStale {
		c.triggerBackgroundSync()
	}

	// Handle staleness policy for expired data
	if freshness == FreshnessStateExpired {
		switch c.policy.StalePolicy {
		case StalePolicyFailClosed:
			return false, FreshnessStateExpired, &StaleRevocationDataError{
				StaleSince: metadata.SyncedAt.Add(c.policy.HardTTL),
			}
		case StalePolicyDegraded:
			c.logger.Warn("using degraded revocation data",
				"stale_since", metadata.SyncedAt.Add(c.policy.HardTTL))
			freshness = FreshnessStateDegraded
		case StalePolicyWarnAndAllow:
			c.logger.Warn("using stale revocation data (dev mode)",
				"stale_since", metadata.SyncedAt.Add(c.policy.HardTTL))
			// Still mark as degraded to indicate non-fresh data
			freshness = FreshnessStateDegraded
		}
	}

	if revoked {
		return true, freshness, nil
	}

	// Check if entry exists but indicates not revoked
	_ = entry // Entry details available if needed for audit

	return false, freshness, nil
}

// GetRevocationDetails returns details about a revoked JTI.
func (c *RevocationCache) GetRevocationDetails(jti string) (*RevocationEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.revoked[jti]
	if !ok {
		return nil, false
	}
	return entry, true
}

// Add adds a revocation entry. Used during sync and bootstrap.
func (c *RevocationCache) Add(entry RevocationEntry) {
	c.mu.Lock()
	c.revoked[entry.JTI] = &entry
	c.mu.Unlock()
}

// AddBatch adds multiple revocation entries efficiently.
func (c *RevocationCache) AddBatch(entries []RevocationEntry) {
	c.mu.Lock()
	for i := range entries {
		c.revoked[entries[i].JTI] = &entries[i]
	}
	c.mu.Unlock()
}

// SetSyncMetadata updates the sync cursor and timestamp.
func (c *RevocationCache) SetSyncMetadata(issuerDID, cursor string) {
	c.mu.Lock()
	c.metadata = &revocationMetadata{
		SyncedAt:     time.Now(),
		Cursor:       cursor,
		IssuerDID:    issuerDID,
		TotalRevoked: len(c.revoked),
	}
	c.mu.Unlock()

	// Persist both metadata and revocations to disk
	if c.dir != "" {
		if err := c.SaveToDisk(); err != nil {
			c.logger.Warn("failed to persist revocation cache", "error", err)
		}
	}
}

// GetSyncCursor returns the current sync cursor for delta sync.
func (c *RevocationCache) GetSyncCursor() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metadata.Cursor
}

// LastSyncTime returns when the cache was last synchronized.
func (c *RevocationCache) LastSyncTime() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metadata.SyncedAt
}

// LoadFromBundle imports revocation data from an exported bundle.
func (c *RevocationCache) LoadFromBundle(bundle *TrustMaterial) error {
	if bundle.Revocations == nil {
		return nil
	}

	c.mu.Lock()
	for jti, entry := range bundle.Revocations.Revoked {
		c.revoked[jti] = &RevocationEntry{
			JTI:       entry.JTI,
			RevokedAt: entry.RevokedAt,
			Reason:    entry.Reason,
		}
	}
	c.metadata = &revocationMetadata{
		SyncedAt:     bundle.Revocations.SyncedAt,
		Cursor:       bundle.Revocations.Cursor,
		TotalRevoked: len(c.revoked),
	}
	c.mu.Unlock()

	c.logger.Info("loaded revocation bundle",
		"count", len(bundle.Revocations.Revoked),
		"cursor", bundle.Revocations.Cursor)

	return nil
}

// Export creates a revocation set from the current cache state.
func (c *RevocationCache) Export() *RevocationSet {
	c.mu.RLock()
	defer c.mu.RUnlock()

	set := &RevocationSet{
		Revoked:  make(map[string]RevocationEntry),
		SyncedAt: c.metadata.SyncedAt,
		Cursor:   c.metadata.Cursor,
	}

	for jti, entry := range c.revoked {
		set.Revoked[jti] = *entry
	}

	return set
}

// LoadFromDisk loads the cache from disk.
func (c *RevocationCache) LoadFromDisk() error {
	if c.dir == "" {
		return nil
	}

	// Load metadata
	metaPath := filepath.Join(c.dir, "revocations_meta.json")
	if data, err := os.ReadFile(metaPath); err == nil { // #nosec G304 -- path from cache dir config
		var meta revocationMetadata
		if err := json.Unmarshal(data, &meta); err == nil {
			c.mu.Lock()
			c.metadata = &meta
			c.mu.Unlock()
		}
	}

	// Load revocations
	dataPath := filepath.Join(c.dir, "revocations.json")
	data, err := os.ReadFile(dataPath) // #nosec G304 -- path from cache dir config
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No cache file yet
		}
		return err
	}

	var entries map[string]RevocationEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}

	c.mu.Lock()
	for jti, entry := range entries {
		e := entry // Copy to avoid loop variable pointer issue
		c.revoked[jti] = &e
	}
	c.mu.Unlock()

	c.logger.Info("loaded revocations from disk",
		"count", len(entries))

	return nil
}

// SaveToDisk persists the cache to disk.
func (c *RevocationCache) SaveToDisk() error {
	if c.dir == "" {
		return nil
	}

	c.mu.RLock()
	entries := make(map[string]RevocationEntry)
	for jti, entry := range c.revoked {
		entries[jti] = *entry
	}
	metadata := *c.metadata
	c.mu.RUnlock()

	// Save revocations
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	dataPath := filepath.Join(c.dir, "revocations.json")
	if err := os.WriteFile(dataPath, data, 0600); err != nil {
		return err
	}

	// Save metadata
	metaData, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	metaPath := filepath.Join(c.dir, "revocations_meta.json")
	return os.WriteFile(metaPath, metaData, 0600)
}

// Close stops background sync goroutines.
func (c *RevocationCache) Close() error {
	close(c.stopSync)
	c.wg.Wait()
	return c.SaveToDisk()
}

// evaluateFreshness determines the freshness state of the cache.
func (c *RevocationCache) evaluateFreshness(metadata *revocationMetadata) FreshnessState {
	if metadata.SyncedAt.IsZero() {
		return FreshnessStateExpired
	}

	age := time.Since(metadata.SyncedAt)

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

// triggerBackgroundSync starts an async sync if not already pending.
func (c *RevocationCache) triggerBackgroundSync() {
	if c.syncer == nil {
		return
	}

	c.syncMu.Lock()
	if c.syncPending {
		c.syncMu.Unlock()
		return
	}
	c.syncPending = true
	c.syncMu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() {
			c.syncMu.Lock()
			c.syncPending = false
			c.syncMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		c.mu.RLock()
		issuerDID := c.metadata.IssuerDID
		cursor := c.metadata.Cursor
		c.mu.RUnlock()

		entries, newCursor, err := c.syncer.SyncRevocations(ctx, issuerDID, cursor)
		if err != nil {
			c.logger.Warn("background revocation sync failed",
				"error", err)
			return
		}

		c.AddBatch(entries)
		c.SetSyncMetadata(issuerDID, newCursor)

		c.logger.Debug("background revocation sync completed",
			"new_entries", len(entries),
			"cursor", newCursor)
	}()
}

// StaleRevocationDataError indicates revocation data has exceeded HardTTL.
type StaleRevocationDataError struct {
	StaleSince time.Time
}

func (e *StaleRevocationDataError) Error() string {
	return fmt.Sprintf("revocation data is stale (expired %s)", e.StaleSince)
}

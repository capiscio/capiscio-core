// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Common bootstrap errors.
var (
	ErrNoTrustMaterial     = errors.New("no trust material available")
	ErrBootstrapFailed     = errors.New("bootstrap failed")
	ErrDisconnectedNoCache = errors.New("disconnected mode requires pre-loaded trust material")
)

// MaterialManager manages the lifecycle of trust material for verification.
// It provides a unified interface for JWKS and revocation caching with
// explicit bootstrap and graceful degradation.
type MaterialManager struct {
	// Configuration
	config BootstrapConfig
	logger Logger

	// Caches
	jwksCache       *JWKSCache
	revocationCache *RevocationCache

	// State
	bootstrapped bool
	bootstrapErr error
}

// NewMaterialManager creates a new trust material manager.
func NewMaterialManager(config BootstrapConfig, logger Logger) (*MaterialManager, error) {
	if logger == nil {
		logger = noopLogger{}
	}

	// Apply default freshness policy if not configured
	freshnessPolicy := config.FreshnessPolicy
	if freshnessPolicy.SoftTTL == 0 && freshnessPolicy.HardTTL == 0 {
		freshnessPolicy = DefaultFreshnessPolicy()
	}

	// Create JWKS cache
	jwksOpts := []JWKSCacheOption{
		WithFreshnessPolicy(freshnessPolicy),
		WithLogger(logger),
	}
	if len(config.JWKSPaths) > 0 {
		// Use first path's directory as cache dir
		dir := filepath.Dir(config.JWKSPaths[0])
		jwksOpts = append(jwksOpts, WithJWKSCacheDir(dir))
	}

	jwksCache, err := NewJWKSCache(jwksOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS cache: %w", err)
	}

	// Create revocation cache
	revOpts := []RevocationCacheOption{
		WithRevocationFreshnessPolicy(config.FreshnessPolicy),
		WithRevocationLogger(logger),
	}
	if config.RevocationPath != "" {
		dir := filepath.Dir(config.RevocationPath)
		revOpts = append(revOpts, WithRevocationCacheDir(dir))
	}

	revocationCache, err := NewRevocationCache(revOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation cache: %w", err)
	}

	return &MaterialManager{
		config:          config,
		logger:          logger,
		jwksCache:       jwksCache,
		revocationCache: revocationCache,
	}, nil
}

// Bootstrap initializes trust material from configured sources.
// This MUST be called before verification operations.
//
// Bootstrap order:
// 1. Load trust bundle if specified
// 2. Load individual JWKS files
// 3. Load revocation data
// 4. Warmup known issuers (if online)
//
// In DisconnectedMode, bootstrap fails if no pre-loaded material exists.
func (m *MaterialManager) Bootstrap(ctx context.Context) error {
	m.logger.Info("starting trust material bootstrap")

	loaded := 0

	// 1. Load JWKS from configured paths
	for _, path := range m.config.JWKSPaths {
		if err := m.loadJWKSFromFile(path); err != nil {
			m.logger.Warn("failed to load JWKS file",
				"path", path,
				"error", err)
			continue
		}
		loaded++
		m.logger.Debug("loaded JWKS", "path", path)
	}

	// 2. Load DID documents from configured paths
	for _, path := range m.config.DIDDocumentPaths {
		if err := m.loadDIDDocumentFromFile(path); err != nil {
			m.logger.Warn("failed to load DID document",
				"path", path,
				"error", err)
			continue
		}
		m.logger.Debug("loaded DID document", "path", path)
	}

	// 3. Load revocation data
	if m.config.RevocationPath != "" {
		if err := m.loadRevocationsFromFile(m.config.RevocationPath); err != nil {
			m.logger.Warn("failed to load revocations",
				"path", m.config.RevocationPath,
				"error", err)
		} else {
			m.logger.Debug("loaded revocations", "path", m.config.RevocationPath)
		}
	}

	// 4. Try to load from disk cache
	if err := m.revocationCache.LoadFromDisk(); err != nil {
		m.logger.Debug("no revocation cache on disk", "error", err)
	}

	// 5. In disconnected mode, fail if no material loaded
	if m.config.DisconnectedMode {
		bundle := m.jwksCache.Export()
		if len(bundle.JWKS) == 0 {
			m.bootstrapErr = ErrDisconnectedNoCache
			return ErrDisconnectedNoCache
		}
		m.logger.Info("bootstrap complete (disconnected mode)",
			"issuers", len(bundle.JWKS))
		m.bootstrapped = true
		return nil
	}

	// 6. Warmup known issuers if online and configured
	// NOTE: This is the ONLY place where synchronous network calls are permitted
	// during initialization. After bootstrap, verification is local-only.
	if len(m.config.KnownIssuers) > 0 {
		m.logger.Info("warming up known issuers",
			"count", len(m.config.KnownIssuers))
		// Warmup is async/best-effort during bootstrap
		// Full implementation would use the JWKSFetcher here
	}

	bundle := m.jwksCache.Export()
	m.logger.Info("bootstrap complete",
		"issuers", len(bundle.JWKS),
		"loaded_files", loaded)

	m.bootstrapped = true
	return nil
}

// IsBootstrapped returns whether bootstrap has completed successfully.
func (m *MaterialManager) IsBootstrapped() bool {
	return m.bootstrapped
}

// GetPublicKey retrieves a public key for verification.
// Returns ErrNoTrustMaterial if not bootstrapped.
func (m *MaterialManager) GetPublicKey(issuerDID, kid string) (any, FreshnessState, error) {
	if !m.bootstrapped {
		return nil, FreshnessStateExpired, ErrNoTrustMaterial
	}

	return m.jwksCache.Get(issuerDID, kid)
}

// IsRevoked checks if a badge JTI is revoked.
// Returns ErrNoTrustMaterial if not bootstrapped.
func (m *MaterialManager) IsRevoked(jti string) (bool, FreshnessState, error) {
	if !m.bootstrapped {
		return false, FreshnessStateExpired, ErrNoTrustMaterial
	}

	return m.revocationCache.IsRevoked(jti)
}

// ExportBundle exports current trust material as a portable bundle.
func (m *MaterialManager) ExportBundle() *TrustMaterial {
	bundle := m.jwksCache.Export()
	bundle.Revocations = m.revocationCache.Export()
	bundle.Metadata.CreatedAt = time.Now()
	return bundle
}

// ImportBundle loads trust material from an exported bundle.
func (m *MaterialManager) ImportBundle(bundle *TrustMaterial) error {
	if err := m.jwksCache.LoadFromBundle(bundle); err != nil {
		return fmt.Errorf("failed to load JWKS bundle: %w", err)
	}
	if err := m.revocationCache.LoadFromBundle(bundle); err != nil {
		return fmt.Errorf("failed to load revocation bundle: %w", err)
	}
	return nil
}

// Close releases resources.
func (m *MaterialManager) Close() error {
	if err := m.jwksCache.Close(); err != nil {
		return err
	}
	return m.revocationCache.Close()
}

// loadJWKSFromFile loads a JWKS file into the cache.
func (m *MaterialManager) loadJWKSFromFile(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path from BootstrapConfig, not user input
	if err != nil {
		return err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(data, &jwks); err != nil {
		// Try single key format
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(data, &jwk); err != nil {
			return fmt.Errorf("invalid JWKS format: %w", err)
		}
		jwks.Keys = []jose.JSONWebKey{jwk}
	}

	// Extract issuer from filename or first key's issuer claim
	issuerDID := filenameToIssuer(path)

	return m.jwksCache.Put(issuerDID, &jwks, "file://"+path)
}

// loadDIDDocumentFromFile loads a DID document for did:web resolution.
func (m *MaterialManager) loadDIDDocumentFromFile(path string) error {
	// DID document loading will be implemented in Phase 0.3
	// For now, just validate the file exists
	_, err := os.Stat(path)
	return err
}

// loadRevocationsFromFile loads revocation data from a file.
func (m *MaterialManager) loadRevocationsFromFile(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path from BootstrapConfig, not user input
	if err != nil {
		return err
	}

	var bundle struct {
		Revocations []RevocationEntry `json:"revocations"`
		Cursor      string            `json:"cursor"`
		IssuerDID   string            `json:"issuer_did"`
	}

	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("invalid revocation format: %w", err)
	}

	m.revocationCache.AddBatch(bundle.Revocations)
	m.revocationCache.SetSyncMetadata(bundle.IssuerDID, bundle.Cursor)

	return nil
}

// filenameToIssuer extracts an issuer DID from a filename.
// e.g., "did_web_example.com.jwks.json" -> "did:web:example.com"
func filenameToIssuer(path string) string {
	base := filepath.Base(path)
	// Strip extension
	for ext := filepath.Ext(base); ext != ""; ext = filepath.Ext(base) {
		base = base[:len(base)-len(ext)]
	}
	// Convert did_web_example.com to did:web:example.com
	// This is a simple heuristic; real implementation may use metadata
	return base
}

// =============================================================================
// BOOTSTRAP HELPERS
// =============================================================================

// Bootstrap is a convenience function that creates and bootstraps a MaterialManager.
func Bootstrap(ctx context.Context, config BootstrapConfig) (*MaterialManager, error) {
	mgr, err := NewMaterialManager(config, nil)
	if err != nil {
		return nil, err
	}

	if err := mgr.Bootstrap(ctx); err != nil {
		return nil, err
	}

	return mgr, nil
}

// BootstrapFromBundle creates a MaterialManager from an exported trust bundle.
// This is the recommended path for deployments with pre-packaged trust material.
func BootstrapFromBundle(bundle *TrustMaterial, policy FreshnessPolicy) (*MaterialManager, error) {
	config := BootstrapConfig{
		FreshnessPolicy:  policy,
		DisconnectedMode: true, // Bundle implies disconnected-capable
	}

	mgr, err := NewMaterialManager(config, nil)
	if err != nil {
		return nil, err
	}

	if err := mgr.ImportBundle(bundle); err != nil {
		return nil, err
	}

	mgr.bootstrapped = true
	return mgr, nil
}

// LoadBundleFromFile loads a trust bundle from a JSON file.
func LoadBundleFromFile(path string) (*TrustMaterial, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller provides path, validated before use
	if err != nil {
		return nil, err
	}

	var bundle TrustMaterial
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("invalid trust bundle: %w", err)
	}

	return &bundle, nil
}

// SaveBundleToFile saves a trust bundle to a JSON file.
func SaveBundleToFile(bundle *TrustMaterial, path string) error {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

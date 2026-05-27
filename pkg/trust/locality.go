// Package trust provides a local trust store for CA public keys.
// This file defines the Verification Locality invariants per RFC-001 §2.3.
//
// VERIFICATION LOCALITY PRINCIPLE (RFC-001 §2.3)
//
// Runtime trust verification MUST NOT require synchronous interaction with the
// Registry or any centralized service. All trust artifacts produced by CapiscIO —
// Badges (RFC-002), Authority Envelopes (RFC-008), Hop Attestations (RFC-004) —
// are cryptographically self-verifiable.
//
// The architecture treats issuance and verification as strictly separate concerns:
//
//	| Concern           | Network Required |
//	|-------------------|------------------|
//	| Issuance          | Yes              |
//	| Verification      | No               |
//	| Revocation        | Recommended (async) |
//	| Trust Augmentation| Optional         |
//
// NORMATIVE REQUIREMENTS:
//
//  1. Verifiers MUST be able to validate any CapiscIO trust artifact using only
//     locally cached cryptographic material and a local revocation cache.
//
//  2. Implementations MUST NOT embed synchronous registry calls in the
//     verification critical path.
//
//  3. SDK and library implementations MUST provide a verification API that
//     operates without network access when initialized with issuer key material.
//
//  4. The Registry MUST publish issuer keys via a cacheable JWKS endpoint.
//     Verifiers SHOULD cache this material with a TTL appropriate to their
//     security posture.
//
//  5. Revocation data MUST be distributable as a cacheable artifact.
//     Verifiers synchronize revocation state asynchronously, not per-verification.
package trust

import (
	"crypto"
	"time"
)

// =============================================================================
// VERIFICATION LOCALITY TYPES
// =============================================================================

// TrustMaterial holds all cached trust data required for local-first verification.
// A verifier initialized with TrustMaterial can perform all verification operations
// without network access.
type TrustMaterial struct {
	// JWKS contains issuer key material, keyed by issuer DID.
	JWKS map[string]*IssuerKeys

	// Revocations contains revoked badge JTIs.
	Revocations *RevocationSet

	// DIDDocuments contains pre-resolved DID documents for did:web issuers.
	// This enables verification of did:web-based envelopes without HTTP fetch.
	DIDDocuments map[string]*CachedDIDDocument

	// Metadata tracks freshness and provenance.
	Metadata MaterialMetadata
}

// IssuerKeys holds JWKS material for a single issuer.
type IssuerKeys struct {
	IssuerDID  string
	Keys       []crypto.PublicKey
	FetchedAt  time.Time
	ExpiresAt  time.Time
	SourceURL  string // Original JWKS endpoint
}

// RevocationSet holds revoked JTIs with sync metadata.
type RevocationSet struct {
	Revoked  map[string]RevocationEntry
	SyncedAt time.Time
	Cursor   string // For delta sync
}

// RevocationEntry records a single revocation.
type RevocationEntry struct {
	JTI       string
	RevokedAt time.Time
	Reason    string
}

// CachedDIDDocument holds a pre-resolved DID document.
type CachedDIDDocument struct {
	DID        string
	Document   []byte // Raw JSON
	FetchedAt  time.Time
	ExpiresAt  time.Time
	SourceURL  string
}

// MaterialMetadata tracks freshness and bootstrap state.
type MaterialMetadata struct {
	CreatedAt    time.Time
	LastRefresh  time.Time
	BootstrapID  string // Identifies the trust bundle source
	Version      string // Trust bundle version
}

// =============================================================================
// FRESHNESS POLICY
// =============================================================================

// FreshnessPolicy defines staleness behavior per RFC-001 §2.3 + implementation guidance.
type FreshnessPolicy struct {
	// SoftTTL is the target refresh interval. After SoftTTL, background
	// refresh is triggered but verification continues normally.
	SoftTTL time.Duration // Default: 1 hour

	// HardTTL is the maximum staleness. After HardTTL, the StalePolicy applies.
	HardTTL time.Duration // Default: 24 hours

	// StalePolicy determines behavior when trust material exceeds HardTTL.
	StalePolicy StalePolicy // Default: WarnAndAllow for dev, FailClosed for prod

	// GracePeriod is additional time after HardTTL before FailClosed kicks in.
	GracePeriod time.Duration // Default: 1 hour

	// RefreshBackoff controls retry behavior during refresh failures.
	RefreshBackoff BackoffConfig
}

// StalePolicy determines behavior when trust material exceeds HardTTL.
type StalePolicy int

const (
	// StalePolicyWarnAndAllow logs warning, allows verification.
	// Use for development/testing only.
	StalePolicyWarnAndAllow StalePolicy = iota

	// StalePolicyDegraded allows verification but marks result as degraded.
	// Useful for observability without hard failures.
	StalePolicyDegraded

	// StalePolicyFailClosed denies verification until refresh succeeds.
	// RECOMMENDED for production per RFC-001 §2.3.
	StalePolicyFailClosed
)

// BackoffConfig controls retry behavior.
type BackoffConfig struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	MaxRetries   int
}

// DefaultFreshnessPolicy returns recommended defaults for production.
func DefaultFreshnessPolicy() FreshnessPolicy {
	return FreshnessPolicy{
		SoftTTL:     1 * time.Hour,
		HardTTL:     24 * time.Hour,
		StalePolicy: StalePolicyFailClosed,
		GracePeriod: 1 * time.Hour,
		RefreshBackoff: BackoffConfig{
			InitialDelay: 5 * time.Second,
			MaxDelay:     5 * time.Minute,
			Multiplier:   2.0,
			MaxRetries:   10,
		},
	}
}

// =============================================================================
// BOOTSTRAP CONFIGURATION
// =============================================================================

// BootstrapConfig defines initialization options for verifiers.
type BootstrapConfig struct {
	// JWKSPaths lists local files to load JWKS from at startup.
	// Enables verification without synchronous server call from first invocation.
	JWKSPaths []string

	// RevocationPath is a local file with pre-loaded revocation state.
	RevocationPath string

	// DIDDocumentPaths lists local files with pre-resolved DID documents.
	DIDDocumentPaths []string

	// KnownIssuers lists issuer DIDs to warmup at startup.
	// If online, will fetch and cache JWKS for these issuers.
	KnownIssuers []string

	// DisconnectedMode disables all background refresh and network fetches.
	// Verification operates purely against loaded trust material.
	// Use for testing or environments with no network access.
	DisconnectedMode bool

	// FreshnessPolicy controls staleness behavior.
	FreshnessPolicy FreshnessPolicy
}

// =============================================================================
// VERIFICATION RESULT FRESHNESS
// =============================================================================

// FreshnessState indicates the freshness of trust material used for verification.
type FreshnessState int

const (
	// FreshnessStateFresh indicates trust material is within SoftTTL.
	FreshnessStateFresh FreshnessState = iota

	// FreshnessStateStale indicates trust material exceeded SoftTTL but within HardTTL.
	FreshnessStateStale

	// FreshnessStateDegraded indicates verification proceeded with stale material
	// (only possible with StalePolicyDegraded or StalePolicyWarnAndAllow).
	FreshnessStateDegraded

	// FreshnessStateExpired indicates trust material exceeded HardTTL + GracePeriod.
	// Verification should have failed if StalePolicy was FailClosed.
	FreshnessStateExpired
)

// String returns a human-readable freshness state.
func (f FreshnessState) String() string {
	switch f {
	case FreshnessStateFresh:
		return "fresh"
	case FreshnessStateStale:
		return "stale"
	case FreshnessStateDegraded:
		return "degraded"
	case FreshnessStateExpired:
		return "expired"
	default:
		return "unknown"
	}
}

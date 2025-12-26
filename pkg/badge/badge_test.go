package badge_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRegistry is a simple in-memory registry for testing.
type MockRegistry struct {
	Keys               map[string]crypto.PublicKey
	RevokedBadges      map[string]bool
	AgentStatuses      map[string]string
	ForceError         error // If set, all methods return this error
	ForceRevCheckError error // If set, only revocation check methods fail
}

func (m *MockRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
	if m.ForceError != nil {
		return nil, m.ForceError
	}
	if key, ok := m.Keys[issuer]; ok {
		return key, nil
	}
	return nil, assert.AnError
}

func (m *MockRegistry) IsRevoked(ctx context.Context, id string) (bool, error) {
	if m.ForceError != nil {
		return false, m.ForceError
	}
	if m.ForceRevCheckError != nil {
		return false, m.ForceRevCheckError
	}
	if m.RevokedBadges != nil {
		return m.RevokedBadges[id], nil
	}
	return false, nil
}

func (m *MockRegistry) GetBadgeStatus(ctx context.Context, issuerURL string, jti string) (*registry.BadgeStatus, error) {
	if m.ForceError != nil {
		return nil, m.ForceError
	}
	if m.ForceRevCheckError != nil {
		return nil, m.ForceRevCheckError
	}
	if m.RevokedBadges != nil && m.RevokedBadges[jti] {
		return &registry.BadgeStatus{JTI: jti, Revoked: true}, nil
	}
	return &registry.BadgeStatus{JTI: jti, Revoked: false}, nil
}

func (m *MockRegistry) GetAgentStatus(ctx context.Context, issuerURL string, agentID string) (*registry.AgentStatus, error) {
	if m.ForceError != nil {
		return nil, m.ForceError
	}
	if m.ForceRevCheckError != nil {
		return nil, m.ForceRevCheckError
	}
	if m.AgentStatuses != nil {
		if status, ok := m.AgentStatuses[agentID]; ok {
			return &registry.AgentStatus{ID: agentID, Status: status}, nil
		}
	}
	return &registry.AgentStatus{ID: agentID, Status: registry.AgentStatusActive}, nil
}

func (m *MockRegistry) SyncRevocations(ctx context.Context, issuerURL string, since time.Time) ([]registry.Revocation, error) {
	if m.ForceError != nil {
		return nil, m.ForceError
	}
	if m.ForceRevCheckError != nil {
		return nil, m.ForceRevCheckError
	}
	return nil, nil
}

// SetPublicKey sets a public key for an issuer in the mock registry.
func (m *MockRegistry) SetPublicKey(issuer string, key crypto.PublicKey) {
	if m.Keys == nil {
		m.Keys = make(map[string]crypto.PublicKey)
	}
	m.Keys[issuer] = key
}

// SetError sets an error that will be returned by all methods.
func (m *MockRegistry) SetError(err error) {
	m.ForceError = err
}

// SetRevocationError sets an error that will be returned only by revocation methods.
func (m *MockRegistry) SetRevocationError(err error) {
	m.ForceRevCheckError = err
}

// newMockRegistryForTest creates a new mock registry for testing.
func newMockRegistryForTest() *MockRegistry {
	return &MockRegistry{
		Keys:          make(map[string]crypto.PublicKey),
		RevokedBadges: make(map[string]bool),
		AgentStatuses: make(map[string]string),
	}
}

func TestBadgeLifecycle(t *testing.T) {
	// 1. Setup Keys
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use proper did:web format for issuer
	issuerDID := "did:web:test-registry.capisc.io"
	reg := &MockRegistry{
		Keys: map[string]crypto.PublicKey{
			issuerDID: pub,
		},
	}
	verifier := badge.NewVerifier(reg)

	// 2. Create Valid Badge (with all RFC-002 required fields)
	now := time.Now()
	claims := &badge.Claims{
		JTI:      "test-jti-12345",
		Issuer:   issuerDID,
		Subject:  "did:web:test-registry.capisc.io:agents:test",
		IssuedAt: now.Unix(),
		Expiry:   now.Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "1",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// 3. Verify Valid Badge
	verifiedClaims, err := verifier.Verify(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, claims.Subject, verifiedClaims.Subject)
	assert.Equal(t, claims.Issuer, verifiedClaims.Issuer)
	assert.Equal(t, claims.JTI, verifiedClaims.JTI)

	// 4. Test Expired Badge
	expiredClaims := *claims
	expiredClaims.JTI = "expired-badge"
	expiredClaims.Expiry = now.Add(-1 * time.Hour).Unix() // Expired 1 hour ago
	expiredToken, err := badge.SignBadge(&expiredClaims, priv)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), expiredToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BADGE_EXPIRED")

	// 5. Test Invalid Signature (Wrong Key)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedToken, err := badge.SignBadge(claims, wrongPriv) // Signed by wrong key
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), forgedToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BADGE_SIGNATURE_INVALID")
}

func TestBadgeVerifyWithOptions(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use proper did:web format for issuer
	issuerDID := "did:web:test-registry.capisc.io"
	reg := &MockRegistry{
		Keys: map[string]crypto.PublicKey{
			issuerDID: pub,
		},
	}
	verifier := badge.NewVerifier(reg)

	now := time.Now()
	claims := &badge.Claims{
		JTI:      "test-jti-options",
		Issuer:   issuerDID,
		Subject:  "did:web:test-registry.capisc.io:agents:test",
		Audience: []string{"https://api.example.com"},
		IssuedAt: now.Unix(),
		Expiry:   now.Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "2",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	t.Run("audience match", func(t *testing.T) {
		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			Audience:             "https://api.example.com",
			SkipRevocationCheck:  true,
			SkipAgentStatusCheck: true,
		}
		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		require.NoError(t, err)
		assert.Equal(t, "2", result.Claims.TrustLevel())
	})

	t.Run("audience mismatch", func(t *testing.T) {
		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			Audience:             "https://other.example.com",
			SkipRevocationCheck:  true,
			SkipAgentStatusCheck: true,
		}
		_, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "BADGE_AUDIENCE_MISMATCH")
	})

	t.Run("trusted issuer match", func(t *testing.T) {
		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			TrustedIssuers:       []string{issuerDID},
			SkipRevocationCheck:  true,
			SkipAgentStatusCheck: true,
		}
		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		require.NoError(t, err)
		assert.NotNil(t, result.Claims)
	})

	t.Run("trusted issuer mismatch", func(t *testing.T) {
		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			TrustedIssuers:       []string{"did:web:other-registry.capisc.io"},
			SkipRevocationCheck:  true,
			SkipAgentStatusCheck: true,
		}
		_, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "BADGE_ISSUER_UNTRUSTED")
	})
}

func TestBadgeRevocation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use proper did:web format for issuer
	issuerDID := "did:web:test-registry.capisc.io"
	reg := &MockRegistry{
		Keys: map[string]crypto.PublicKey{
			issuerDID: pub,
		},
		RevokedBadges: map[string]bool{
			"revoked-badge": true,
		},
	}
	verifier := badge.NewVerifier(reg)

	now := time.Now()
	claims := &badge.Claims{
		JTI:      "revoked-badge",
		Issuer:   issuerDID,
		Subject:  "did:web:test-registry.capisc.io:agents:test",
		IssuedAt: now.Unix(),
		Expiry:   now.Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "1",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BADGE_REVOKED")
}

func TestBadgeAgentDisabled(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use proper did:web format for issuer
	issuerDID := "did:web:test-registry.capisc.io"
	reg := &MockRegistry{
		Keys: map[string]crypto.PublicKey{
			issuerDID: pub,
		},
		AgentStatuses: map[string]string{
			"disabled-agent": registry.AgentStatusDisabled,
		},
	}
	verifier := badge.NewVerifier(reg)

	now := time.Now()
	claims := &badge.Claims{
		JTI:      "badge-for-disabled-agent",
		Issuer:   issuerDID,
		Subject:  "did:web:test-registry.capisc.io:agents:disabled-agent",
		IssuedAt: now.Unix(),
		Expiry:   now.Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "1",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BADGE_AGENT_DISABLED")
}

func TestClaimsHelpers(t *testing.T) {
	claims := &badge.Claims{
		JTI:      "test-jti",
		Subject:  "did:web:registry.capisc.io:agents:my-agent-001",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "example.com",
				Level:  "2",
			},
		},
	}

	t.Run("AgentID", func(t *testing.T) {
		assert.Equal(t, "my-agent-001", claims.AgentID())
	})

	t.Run("TrustLevel", func(t *testing.T) {
		assert.Equal(t, "2", claims.TrustLevel())
	})

	t.Run("Domain", func(t *testing.T) {
		assert.Equal(t, "example.com", claims.Domain())
	})

	t.Run("IsExpired", func(t *testing.T) {
		assert.False(t, claims.IsExpired())

		expiredClaims := *claims
		expiredClaims.Expiry = time.Now().Add(-1 * time.Hour).Unix()
		assert.True(t, expiredClaims.IsExpired())
	})

	t.Run("IsNotYetValid", func(t *testing.T) {
		assert.False(t, claims.IsNotYetValid())

		futureClaims := *claims
		futureClaims.IssuedAt = time.Now().Add(1 * time.Hour).Unix()
		assert.True(t, futureClaims.IsNotYetValid())
	})
}

// ============================================================================
// Self-Signed Badge Tests (RFC-002 v1.1 Level 0)
// ============================================================================

func TestSelfSignedBadge(t *testing.T) {
	// Generate a key pair for self-signing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create did:key from the public key
	didKey := did.NewKeyDID(pub)

	// Create a mock registry (won't be used for self-signed)
	reg := &MockRegistry{
		Keys: map[string]crypto.PublicKey{},
	}
	verifier := badge.NewVerifier(reg)

	now := time.Now()

	t.Run("valid self-signed badge with AcceptSelfSigned", func(t *testing.T) {
		// Level 0 self-signed badge: iss == sub == did:key
		claims := &badge.Claims{
			JTI:      "self-signed-badge-001",
			Issuer:   didKey,
			Subject:  didKey, // iss == sub for self-signed
			IssuedAt: now.Unix(),
			Expiry:   now.Add(1 * time.Hour).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "self-signed.example.com",
					Level:  "0", // Must be Level 0 for self-signed
				},
			},
		}

		token, err := badge.SignBadge(claims, priv)
		require.NoError(t, err)

		opts := badge.VerifyOptions{
			Mode:             badge.VerifyModeOffline, // No registry access needed
			AcceptSelfSigned: true,
		}
		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		require.NoError(t, err)
		assert.Equal(t, didKey, result.Claims.Issuer)
		assert.Equal(t, didKey, result.Claims.Subject)
		assert.Equal(t, "0", result.Claims.TrustLevel())
		// Should have warnings about skipped checks
		assert.Contains(t, result.Warnings, "revocation check skipped (self-signed badge)")
		assert.Contains(t, result.Warnings, "agent status check skipped (self-signed badge)")
	})

	t.Run("self-signed badge rejected without AcceptSelfSigned", func(t *testing.T) {
		claims := &badge.Claims{
			JTI:      "self-signed-badge-002",
			Issuer:   didKey,
			Subject:  didKey,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(1 * time.Hour).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "self-signed.example.com",
					Level:  "0",
				},
			},
		}

		token, err := badge.SignBadge(claims, priv)
		require.NoError(t, err)

		opts := badge.VerifyOptions{
			Mode:             badge.VerifyModeOffline,
			AcceptSelfSigned: false, // Default - reject self-signed
		}
		_, err = verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "self-signed badges")
		assert.Contains(t, err.Error(), "BADGE_ISSUER_UNTRUSTED")
	})

	t.Run("self-signed badge with explicitly trusted did:key", func(t *testing.T) {
		claims := &badge.Claims{
			JTI:      "self-signed-badge-003",
			Issuer:   didKey,
			Subject:  didKey,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(1 * time.Hour).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "self-signed.example.com",
					Level:  "0",
				},
			},
		}

		token, err := badge.SignBadge(claims, priv)
		require.NoError(t, err)

		opts := badge.VerifyOptions{
			Mode:             badge.VerifyModeOffline,
			AcceptSelfSigned: false,
			TrustedIssuers:   []string{didKey}, // Explicitly trust this did:key
		}
		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		require.NoError(t, err)
		assert.Equal(t, "0", result.Claims.TrustLevel())
	})

	t.Run("self-signed badge with wrong level rejected", func(t *testing.T) {
		// Try to claim Level 1 with did:key issuer - should be rejected
		claims := &badge.Claims{
			JTI:      "self-signed-badge-004",
			Issuer:   didKey,
			Subject:  didKey,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(1 * time.Hour).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "self-signed.example.com",
					Level:  "1", // Invalid - did:key must be Level 0
				},
			},
		}

		token, err := badge.SignBadge(claims, priv)
		require.NoError(t, err)

		opts := badge.VerifyOptions{
			Mode:             badge.VerifyModeOffline,
			AcceptSelfSigned: true,
		}
		_, err = verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "BADGE_CLAIMS_INVALID")
		assert.Contains(t, err.Error(), "level \"0\"")
	})

	t.Run("self-signed badge with iss != sub rejected", func(t *testing.T) {
		// Try to issue badge for different subject - should be rejected
		claims := &badge.Claims{
			JTI:      "self-signed-badge-005",
			Issuer:   didKey,
			Subject:  "did:web:example.com:agents:other-agent", // Different from issuer
			IssuedAt: now.Unix(),
			Expiry:   now.Add(1 * time.Hour).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "self-signed.example.com",
					Level:  "0",
				},
			},
		}

		token, err := badge.SignBadge(claims, priv)
		require.NoError(t, err)

		opts := badge.VerifyOptions{
			Mode:             badge.VerifyModeOffline,
			AcceptSelfSigned: true,
		}
		_, err = verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "BADGE_CLAIMS_INVALID")
		assert.Contains(t, err.Error(), "iss == sub")
	})
}

// mockStaleCache is a mock revocation cache that can be configured for staleness.
type mockStaleCache struct {
	revokedJTIs map[string]bool
	stale       bool
}

func newMockStaleCache(stale bool) *mockStaleCache {
	return &mockStaleCache{
		revokedJTIs: make(map[string]bool),
		stale:       stale,
	}
}

func (c *mockStaleCache) IsRevoked(jti string) bool {
	return c.revokedJTIs[jti]
}

func (c *mockStaleCache) IsStale(threshold time.Duration) bool {
	return c.stale
}

func (c *mockStaleCache) AddRevoked(jti string) {
	c.revokedJTIs[jti] = true
}

// TestStalenessFailClosed tests RFC-002 v1.3 staleness fail-closed behavior.
func TestStalenessFailClosed(t *testing.T) {
	// Create a mock registry (doesn't need to work for offline mode)
	mockReg := newMockRegistryForTest()
	verifier := badge.NewVerifier(mockReg)

	// Create a valid IAL-2 badge
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	issuerDID := "did:web:ca.capisc.io"
	subjectDID := "did:web:example.com:agents:test-agent"
	now := time.Now()

	createBadge := func(level string) string {
		claims := &badge.Claims{
			JTI:      fmt.Sprintf("staleness-test-%s-%d", level, time.Now().UnixNano()),
			Issuer:   issuerDID,
			Subject:  subjectDID,
			IssuedAt: now.Unix(),
			Expiry:   now.Add(1 * time.Hour).Unix(),
			VC: badge.VerifiableCredential{
				Type: []string{"VerifiableCredential", "AgentIdentity"},
				CredentialSubject: badge.CredentialSubject{
					Domain: "example.com",
					Level:  level,
				},
			},
		}
		token, _ := badge.SignBadge(claims, priv)
		return token
	}

	// Configure mock registry to return our public key
	mockReg.SetPublicKey(issuerDID, pub)

	t.Run("stale cache fails IAL-2 in offline mode", func(t *testing.T) {
		cache := newMockStaleCache(true) // Stale cache
		token := createBadge("2")

		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOffline,
			RevocationCache:      cache,
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: true,
			TrustedIssuers:       []string{issuerDID},
		}

		_, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "stale")
		assert.Contains(t, err.Error(), "fail-closed")
		// RFC-002 v1.3 §7.5: MUST use REVOCATION_CHECK_FAILED error code
		assert.Contains(t, err.Error(), badge.ErrCodeRevocationCheckFailed)
	})

	t.Run("stale cache allows IAL-1 in offline mode", func(t *testing.T) {
		cache := newMockStaleCache(true) // Stale cache
		token := createBadge("1")

		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOffline,
			RevocationCache:      cache,
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: true,
			TrustedIssuers:       []string{issuerDID},
		}

		// IAL-1 should succeed even with stale cache
		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.NoError(t, err)
		assert.Equal(t, "1", result.Claims.TrustLevel())
	})

	t.Run("fresh cache allows IAL-2 in offline mode", func(t *testing.T) {
		cache := newMockStaleCache(false) // Fresh cache
		token := createBadge("2")

		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOffline,
			RevocationCache:      cache,
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: true,
			TrustedIssuers:       []string{issuerDID},
		}

		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.NoError(t, err)
		assert.Equal(t, "2", result.Claims.TrustLevel())
	})

	t.Run("FailOpen allows stale cache for IAL-2", func(t *testing.T) {
		cache := newMockStaleCache(true) // Stale cache
		token := createBadge("2")

		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOffline,
			RevocationCache:      cache,
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: true,
			TrustedIssuers:       []string{issuerDID},
			FailOpen:             true, // Override fail-closed
		}

		// With FailOpen, IAL-2 should succeed even with stale cache
		result, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.NoError(t, err)
		assert.Equal(t, "2", result.Claims.TrustLevel())
	})

	t.Run("no cache fails IAL-2 in offline mode", func(t *testing.T) {
		token := createBadge("2")

		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeOffline,
			RevocationCache:      nil, // No cache
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: true,
			TrustedIssuers:       []string{issuerDID},
		}

		_, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cache required")
	})

	t.Run("hybrid mode falls back to cache and checks staleness", func(t *testing.T) {
		cache := newMockStaleCache(true) // Stale cache
		token := createBadge("2")

		// Configure registry revocation check to fail (simulating network issue)
		// but key lookup still works
		mockReg.SetRevocationError(fmt.Errorf("network error"))

		opts := badge.VerifyOptions{
			Mode:                 badge.VerifyModeHybrid,
			RevocationCache:      cache,
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: true,
			TrustedIssuers:       []string{issuerDID},
		}

		_, err := verifier.VerifyWithOptions(context.Background(), token, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "stale")

		// Reset error state
		mockReg.SetRevocationError(nil)
	})
}

package badge_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRegistry is a simple in-memory registry for testing.
type MockRegistry struct {
	Keys map[string]crypto.PublicKey
}

func (m *MockRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
	if key, ok := m.Keys[issuer]; ok {
		return key, nil
	}
	return nil, assert.AnError
}

func (m *MockRegistry) IsRevoked(ctx context.Context, id string) (bool, error) {
	return false, nil
}

func TestBadgeLifecycle(t *testing.T) {
	// 1. Setup Keys
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	issuerDID := "https://test-registry.capisc.io"
	reg := &MockRegistry{
		Keys: map[string]crypto.PublicKey{
			issuerDID: pub,
		},
	}
	verifier := badge.NewVerifier(reg)

	// 2. Create Valid Badge
	now := time.Now()
	claims := &badge.Claims{
		Issuer:   issuerDID,
		Subject:  "did:capiscio:agent:test",
		IssuedAt: now.Unix(),
		Expiry:   now.Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential"},
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

	// 4. Test Expired Badge
	expiredClaims := *claims
	expiredClaims.Expiry = now.Add(-1 * time.Hour).Unix() // Expired 1 hour ago
	expiredToken, err := badge.SignBadge(&expiredClaims, priv)
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), expiredToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")

	// 5. Test Invalid Signature (Wrong Key)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedToken, err := badge.SignBadge(claims, wrongPriv) // Signed by wrong key
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), forgedToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

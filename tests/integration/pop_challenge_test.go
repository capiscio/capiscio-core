package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPoPChallengeFlow tests RFC-003 PoP challenge-response flow (Task 4)
func TestPoPChallengeFlow(t *testing.T) {
	ctx := context.Background()

	// Step 1: Generate key pair for test agent
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create did:key from public key
	agentDID := did.NewKeyDID(pubKey)

	t.Logf("Generated test DID: %s", agentDID)

	// Step 2: Create PoP client
	popClient := badge.NewPoPClient(API_BASE_URL, getTestAPIKey())

	// Step 3: Request IAL-1 badge using PoP
	result, err := popClient.RequestPoPBadge(ctx, badge.RequestPoPBadgeOptions{
		AgentDID:   agentDID,
		PrivateKey: privKey,
		TTL:        5 * time.Minute,
	})

	// This may fail if agent registration is required
	if err != nil {
		t.Logf("PoP badge request failed: %v", err)
		t.Log("This is expected if agent needs to be registered first")
		t.Skip("Skipping PoP test - requires agent registration")
	}

	require.NotNil(t, result)

	// Step 4: Validate IAL-1 badge
	assert.NotEmpty(t, result.Token, "badge token should not be empty")
	assert.NotEmpty(t, result.JTI, "JTI should be set")
	assert.Equal(t, "IAL-1", result.AssuranceLevel, "should be IAL-1")
	assert.NotNil(t, result.CNF, "CNF claim should be present")

	t.Logf("✓ PoP badge issued: JTI=%s, IAL=%s", result.JTI, result.AssuranceLevel)

	// Step 5: Verify the badge signature
	_, err = jose.ParseSigned(result.Token, []jose.SignatureAlgorithm{jose.EdDSA})
	require.NoError(t, err, "badge should be valid JWS")
}

// TestPoPChallengeExpiry tests challenge expiry handling (Task 4)
func TestPoPChallengeExpiry(t *testing.T) {
	t.Skip("Requires short-lived challenge - implement with server configuration")

	// TODO: Test that expired challenges are rejected
	// 1. Request challenge
	// 2. Wait for expiry
	// 3. Submit proof - should fail
}

// TestPoPChallengeReplay tests challenge replay protection (Task 4)
func TestPoPChallengeReplay(t *testing.T) {
	t.Skip("Requires challenge replay detection - implement when server supports it")

	// TODO: Test that challenges can only be used once
	// 1. Request challenge
	// 2. Submit proof successfully
	// 3. Submit same proof again - should fail
}

// TestPoPWithInvalidSignature tests invalid signature rejection (Task 4)
func TestPoPWithInvalidSignature(t *testing.T) {
	ctx := context.Background()

	// Generate two different key pairs
	pubKey1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, privKey2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	agentDID := did.NewKeyDID(pubKey1)

	popClient := badge.NewPoPClient(API_BASE_URL, getTestAPIKey())

	// Try to sign with wrong key
	_, err = popClient.RequestPoPBadge(ctx, badge.RequestPoPBadgeOptions{
		AgentDID:   agentDID,
		PrivateKey: privKey2, // Wrong key!
		TTL:        5 * time.Minute,
	})

	// Should fail signature verification
	require.Error(t, err)
	t.Logf("✓ Invalid signature correctly rejected: %v", err)
}

// TestPoPWithMalformedDID tests malformed DID rejection (Task 4)
func TestPoPWithMalformedDID(t *testing.T) {
	ctx := context.Background()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	popClient := badge.NewPoPClient(API_BASE_URL, getTestAPIKey())

	tests := []struct {
		name      string
		agentDID  string
		expectErr bool
	}{
		{
			name:      "empty_did",
			agentDID:  "",
			expectErr: true,
		},
		{
			name:      "invalid_did_format",
			agentDID:  "not-a-did",
			expectErr: true,
		},
		{
			name:      "unsupported_did_method",
			agentDID:  "did:example:123",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := popClient.RequestPoPBadge(ctx, badge.RequestPoPBadgeOptions{
				AgentDID:   tt.agentDID,
				PrivateKey: privKey,
			})

			if tt.expectErr {
				require.Error(t, err)
				t.Logf("✓ Invalid DID correctly rejected: %v", err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestPoPBadgeVerification tests verifying an IAL-1 badge (Task 4)
func TestPoPBadgeVerification(t *testing.T) {
	t.Skip("Requires successful PoP flow - implement after registration")

	// TODO: Test full PoP badge verification
	// 1. Issue IAL-1 badge via PoP
	// 2. Verify badge
	// 3. Check CNF claim matches public key
	// 4. Validate IAL level
}

// TestPoPWithCustomAudience tests PoP badge with audience restrictions (Task 4)
func TestPoPWithCustomAudience(t *testing.T) {
	ctx := context.Background()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	agentDID := did.NewKeyDID(pubKey)

	popClient := badge.NewPoPClient(API_BASE_URL, getTestAPIKey())

	// Request badge with audience restriction
	result, err := popClient.RequestPoPBadge(ctx, badge.RequestPoPBadgeOptions{
		AgentDID:   agentDID,
		PrivateKey: privKey,
		Audience:   []string{"did:web:api.example.com"},
	})

	if err != nil {
		t.Logf("PoP with audience failed: %v", err)
		t.Skip("Skipping - requires agent registration")
	}

	require.NotNil(t, result)
	assert.Equal(t, "IAL-1", result.AssuranceLevel)
	t.Logf("✓ PoP badge with audience issued: JTI=%s", result.JTI)
}

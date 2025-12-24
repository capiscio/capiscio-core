package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDVOrderCreation tests DV order creation (Task 5 - RFC-002 v1.2)
func TestDVOrderCreation(t *testing.T) {
	ctx := context.Background()

	// Generate test key pair
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create JWK from public key
	jwk := &jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     "key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	tests := []struct {
		name          string
		domain        string
		challengeType string
		expectStatus  int
	}{
		{
			name:          "create_http01_order",
			domain:        "test.example.com",
			challengeType: "http-01",
			expectStatus:  http.StatusCreated,
		},
		{
			name:          "create_dns01_order",
			domain:        "dns.example.com",
			challengeType: "dns-01",
			expectStatus:  http.StatusCreated,
		},
		{
			name:          "invalid_challenge_type",
			domain:        "test.example.com",
			challengeType: "invalid-challenge",
			expectStatus:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create order request
			reqBody := map[string]interface{}{
				"domain":         tt.domain,
				"challenge_type": tt.challengeType,
				"jwk":            jwk.Public(),
			}

			orderURL := fmt.Sprintf("%s/v1/badges/dv/orders", apiBaseURL)
			orderID, statusCode := createDVOrder(t, ctx, orderURL, reqBody)

			assert.Equal(t, tt.expectStatus, statusCode)

			if statusCode == http.StatusCreated {
				assert.NotEmpty(t, orderID, "order ID should be set")
				t.Logf("✓ Created DV order: %s (domain=%s, type=%s)",
					orderID, tt.domain, tt.challengeType)
			}
		})
	}
}

// TestDVOrderStatus tests retrieving order status (Task 5)
func TestDVOrderStatus(t *testing.T) {
	ctx := context.Background()

	// Create order first
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     "key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	reqBody := map[string]interface{}{
		"domain":         "status.example.com",
		"challenge_type": "http-01",
		"jwk":            jwk.Public(),
	}

	orderURL := fmt.Sprintf("%s/v1/badges/dv/orders", apiBaseURL)
	orderID, statusCode := createDVOrder(t, ctx, orderURL, reqBody)
	require.Equal(t, http.StatusCreated, statusCode)
	require.NotEmpty(t, orderID)

	// Get order status
	statusURL := fmt.Sprintf("%s/v1/badges/dv/orders/%s", apiBaseURL, orderID)
	resp, err := http.Get(statusURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var order map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&order)
	require.NoError(t, err)

	assert.Equal(t, orderID, order["id"])
	assert.NotEmpty(t, order["status"])
	t.Logf("✓ Order status: %s", order["status"])
}

// TestDVOrderFinalization tests order finalization (Task 6)
func TestDVOrderFinalization(t *testing.T) {
	t.Skip("Requires challenge validation - implement with mock validation")

	// TODO: Implement order finalization test
	// 1. Create order
	// 2. Mock/perform challenge validation
	// 3. Finalize order
	// 4. Receive DV grant
}

// TestDVGrantMinting tests badge minting with DV grant (Task 6)
func TestDVGrantMinting(t *testing.T) {
	t.Skip("Requires finalized order - implement after challenge validation")

	// TODO: Implement grant minting test
	// 1. Create and finalize order
	// 2. Get DV grant
	// 3. Sign PoP proof with grant
	// 4. Mint DV badge (trust level 1)
	// 5. Verify badge claims
}

// TestDVGrantWithDomainMismatch tests domain validation (Task 6)
func TestDVGrantWithDomainMismatch(t *testing.T) {
	t.Skip("Requires finalized grants - implement after minting")

	// TODO: Test that DID domain must match grant domain
	// 1. Create grant for domain A
	// 2. Try to mint badge for domain B
	// 3. Should fail validation
}

// createDVOrder is a helper to create DV orders
func createDVOrder(t *testing.T, ctx context.Context, url string, reqBody map[string]interface{}) (orderID string, statusCode int) {
	bodyBytes, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	if statusCode != http.StatusCreated {
		return "", statusCode
	}

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var orderResp map[string]interface{}
	err = json.Unmarshal(respBody, &orderResp)
	require.NoError(t, err)

	if id, ok := orderResp["id"].(string); ok {
		return id, statusCode
	}

	return "", statusCode
}

// computeJWKThumbprint computes RFC 7638 JWK thumbprint
func computeJWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	// Use crypto.SHA256 constant, not sha256.New function
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	// Base64url encode without padding
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

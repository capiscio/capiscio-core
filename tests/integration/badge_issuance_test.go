package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBadgeIssuance tests badge issuance via server API (Task 2)
// NOTE: These tests require Clerk authentication which is not available in local testing.
// Use the DV flow (test_dv_badge_flow.py) for local integration tests.
func TestBadgeIssuance(t *testing.T) {
	// Skip in local testing - requires Clerk auth
	if os.Getenv("CLERK_SECRET_KEY") == "" {
		t.Skip("CLERK_SECRET_KEY not set - badge issuance tests require Clerk auth. Use DV flow for local testing.")
	}
	
	testAgentID := getTestAgentID()
	if testAgentID == "" {
		t.Skip("TEST_AGENT_ID not set - skipping badge issuance tests")
	}

	tests := []struct {
		name       string
		agentID    string
		domain     string
		trustLevel string
		expectErr  bool
		errCode    string
	}{
		{
			name:       "successful_ial0_badge_issuance",
			agentID:    testAgentID,
			domain:     "example.com",
			trustLevel: "",  // Default to Level 0
			expectErr:  false,
		},
		{
			name:       "badge_issuance_with_custom_ttl",
			agentID:    testAgentID,
			domain:     "api.example.com",
			trustLevel: "",
			expectErr:  false,
		},
		{
			name:       "agent_not_found",
			agentID:    "00000000-0000-0000-0000-000000000000",
			domain:     "example.com",
			expectErr:  true,
			errCode:    "AGENT_NOT_FOUND",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create badge client (requires API key - you'll need to set this up)
			// For now, we'll test the happy path assuming agent exists
			client := badge.NewClient(apiBaseURL, getTestAPIKey())

			// Request badge
			result, err := client.RequestBadge(ctx, badge.RequestBadgeOptions{
				AgentID:    tt.agentID,
				Domain:     tt.domain,
				TTL:        5 * time.Minute,
				TrustLevel: tt.trustLevel,
			})

			if tt.expectErr {
				require.Error(t, err)
				if tt.errCode != "" {
					clientErr, ok := err.(*badge.ClientError)
					require.True(t, ok, "expected ClientError")
					assert.Equal(t, tt.errCode, clientErr.Code)
				}
				return
			}

			// Verify successful issuance
			require.NoError(t, err)
			require.NotNil(t, result)

			// Validate response structure
			assert.NotEmpty(t, result.Token, "badge token should not be empty")
			assert.NotEmpty(t, result.JTI, "badge JTI should not be empty")
			assert.NotEmpty(t, result.Subject, "badge subject should not be empty")
			assert.NotZero(t, result.ExpiresAt, "badge expiry should be set")

			// Verify token can be parsed
			_, err = jose.ParseSigned(result.Token, []jose.SignatureAlgorithm{jose.EdDSA})
			require.NoError(t, err, "badge token should be valid JWS")

			// Log success for debugging
			t.Logf("✓ Issued badge for agent %s: JTI=%s, ExpiresAt=%s",
				tt.agentID, result.JTI, result.ExpiresAt.Format(time.RFC3339))
		})
	}
}

// TestBadgeIssuanceWithPoP tests IAL-1 badge issuance with PoP (Task 4 preview)
func TestBadgeIssuanceWithPoP(t *testing.T) {
	t.Skip("Requires PoP challenge flow - will be implemented in Task 4")

	// TODO: Implement PoP flow test
	// 1. Request challenge
	// 2. Sign challenge with agent private key
	// 3. Submit proof
	// 4. Receive IAL-1 badge with cnf claim
}

// TestBadgeIssuanceEdgeCases tests error conditions
// NOTE: Requires Clerk authentication endpoint
func TestBadgeIssuanceEdgeCases(t *testing.T) {
	if os.Getenv("CLERK_SECRET_KEY") == "" {
		t.Skip("CLERK_SECRET_KEY not set - edge case tests require Clerk auth endpoint")
	}
	
	testAgentID := getTestAgentID()
	if testAgentID == "" {
		t.Skip("TEST_AGENT_ID not set - skipping edge case tests")
	}

	tests := []struct {
		name      string
		apiKey    string
		agentID   string
		expectErr bool
		errCode   string
	}{
		{
			name:      "invalid_api_key",
			apiKey:    "invalid-key-12345",
			agentID:   testAgentID,
			expectErr: true,
			errCode:   "AUTH_INVALID",
		},
		{
			name:      "empty_api_key",
			apiKey:    "",
			agentID:   testAgentID,
			expectErr: true,
			errCode:   "AUTH_INVALID",
		},
		{
			name:      "empty_agent_id",
			apiKey:    getTestAPIKey(),
			agentID:   "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			client := badge.NewClient(apiBaseURL, tt.apiKey)

			_, err := client.RequestBadge(ctx, badge.RequestBadgeOptions{
				AgentID: tt.agentID,
				Domain:  "example.com",
			})

			if tt.expectErr {
				require.Error(t, err)
				if tt.errCode != "" {
					clientErr, ok := err.(*badge.ClientError)
					if ok {
						assert.Equal(t, tt.errCode, clientErr.Code)
					}
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// getTestAPIKey returns test API key from environment
func getTestAPIKey() string {
	if key := os.Getenv("TEST_API_KEY"); key != "" {
		return key
	}
	return "test-api-key-placeholder"
}

// getTestAgentID returns test agent ID from environment
func getTestAgentID() string {
	return os.Getenv("TEST_AGENT_ID")
}

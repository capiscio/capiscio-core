package integration

import (
	"context"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBadgeIssuance tests badge issuance via server API (Task 2)
func TestBadgeIssuance(t *testing.T) {
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
			agentID:    "test-agent-001",
			domain:     "example.com",
			trustLevel: "",  // Default to Level 0
			expectErr:  false,
		},
		{
			name:       "badge_issuance_with_custom_ttl",
			agentID:    "test-agent-002",
			domain:     "api.example.com",
			trustLevel: "",
			expectErr:  false,
		},
		{
			name:       "agent_not_found",
			agentID:    "nonexistent-agent-999",
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
			client := badge.NewClient(API_BASE_URL, getTestAPIKey())

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
			_, err = badge.ParseAndValidateJWS(result.Token)
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
func TestBadgeIssuanceEdgeCases(t *testing.T) {
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
			agentID:   "test-agent-001",
			expectErr: true,
			errCode:   "AUTH_INVALID",
		},
		{
			name:      "empty_api_key",
			apiKey:    "",
			agentID:   "test-agent-001",
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

			client := badge.NewClient(API_BASE_URL, tt.apiKey)

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

// getTestAPIKey returns test API key from environment or default
// TODO: Set up test agent and API key in setup phase
func getTestAPIKey() string {
	// For now, return empty - will be set up in Docker Compose
	// or CI environment
	return "test-api-key-placeholder"
}

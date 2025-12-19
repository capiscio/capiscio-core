package gateway_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/gateway"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRegistry for Gateway tests
type MockRegistry struct {
	Key crypto.PublicKey
}

func (m *MockRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
	return m.Key, nil
}

func (m *MockRegistry) IsRevoked(ctx context.Context, id string) (bool, error) {
	return false, nil
}

func (m *MockRegistry) GetBadgeStatus(ctx context.Context, issuerURL string, jti string) (*registry.BadgeStatus, error) {
	return &registry.BadgeStatus{JTI: jti, Revoked: false}, nil
}

func (m *MockRegistry) GetAgentStatus(ctx context.Context, issuerURL string, agentID string) (*registry.AgentStatus, error) {
	return &registry.AgentStatus{ID: agentID, Status: registry.AgentStatusActive}, nil
}

func (m *MockRegistry) SyncRevocations(ctx context.Context, issuerURL string, since time.Time) ([]registry.Revocation, error) {
	return nil, nil
}

func TestAuthMiddleware(t *testing.T) {
	// 1. Setup Keys and Verifier
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// 2. Create Valid Badge (with RFC-002 required fields)
	// Use proper did:web format for issuer
	claims := &badge.Claims{
		JTI:      "test-jti-gateway",
		Issuer:   "did:web:test.capisc.io",
		Subject:  "did:web:test.capisc.io:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
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

	// 3. Setup Handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		// Verify headers were set
		assert.Equal(t, claims.Subject, r.Header.Get("X-Capiscio-Subject"))
	})

	middleware := gateway.NewAuthMiddleware(verifier, nextHandler)

	// 4. Test Cases
	tests := []struct {
		name           string
		headerKey      string
		headerValue    string
		expectedStatus int
	}{
		{
			name:           "Valid Badge in X-Capiscio-Badge",
			headerKey:      "X-Capiscio-Badge",
			headerValue:    token,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid Badge in Authorization Bearer",
			headerKey:      "Authorization",
			headerValue:    "Bearer " + token,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing Badge",
			headerKey:      "",
			headerValue:    "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Badge",
			headerKey:      "X-Capiscio-Badge",
			headerValue:    "invalid.token.string",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tc.headerKey != "" {
				req.Header.Set(tc.headerKey, tc.headerValue)
			}

			rr := httptest.NewRecorder()
			middleware.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
		})
	}
}

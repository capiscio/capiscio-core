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

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/capiscio/capiscio-core/pkg/gateway"
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

func TestAuthMiddleware(t *testing.T) {
	// 1. Setup Keys and Verifier
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// 2. Create Valid Badge
	claims := &badge.BadgeClaims{
		Issuer:   "https://test.capisc.io",
		Subject:  "did:test:123",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
	}
	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	// 3. Setup Handler
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		// Verify headers were set
		assert.Equal(t, "did:test:123", r.Header.Get("X-Capiscio-Subject"))
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

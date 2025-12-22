// Package badge provides badge client functionality for requesting badges from a CA.
package badge

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPoPClient(t *testing.T) {
	tests := []struct {
		name     string
		caURL    string
		apiKey   string
		wantURL  string
	}{
		{
			name:    "with custom URL",
			caURL:   "https://custom.example.com",
			apiKey:  "test-key",
			wantURL: "https://custom.example.com",
		},
		{
			name:    "with trailing slash",
			caURL:   "https://custom.example.com/",
			apiKey:  "test-key",
			wantURL: "https://custom.example.com",
		},
		{
			name:    "with multiple trailing slashes",
			caURL:   "https://custom.example.com///",
			apiKey:  "test-key",
			wantURL: "https://custom.example.com",
		},
		{
			name:    "empty URL uses default",
			caURL:   "",
			apiKey:  "test-key",
			wantURL: DefaultCAURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewPoPClient(tt.caURL, tt.apiKey)
			assert.Equal(t, tt.wantURL, client.CAURL)
			assert.Equal(t, tt.apiKey, client.APIKey)
			assert.NotNil(t, client.HTTPClient)
			assert.Equal(t, 30*time.Second, client.HTTPClient.Timeout)
		})
	}
}

func TestNewPoPClientWithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 60 * time.Second}

	t.Run("with custom HTTP client", func(t *testing.T) {
		client := NewPoPClientWithHTTPClient("https://example.com", "key", customClient)
		assert.Equal(t, customClient, client.HTTPClient)
		assert.Equal(t, 60*time.Second, client.HTTPClient.Timeout)
	})

	t.Run("with nil HTTP client uses default", func(t *testing.T) {
		client := NewPoPClientWithHTTPClient("https://example.com", "key", nil)
		assert.NotNil(t, client.HTTPClient)
		assert.Equal(t, 30*time.Second, client.HTTPClient.Timeout)
	})
}

func TestRequestPoPBadge_ValidationErrors(t *testing.T) {
	client := NewPoPClient("https://example.com", "test-key")

	tests := []struct {
		name    string
		opts    RequestPoPBadgeOptions
		wantErr string
	}{
		{
			name:    "missing agent DID",
			opts:    RequestPoPBadgeOptions{},
			wantErr: "AgentDID is required",
		},
		{
			name: "missing private key",
			opts: RequestPoPBadgeOptions{
				AgentDID: "did:key:z6MkTest",
			},
			wantErr: "PrivateKey is required for PoP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.RequestPoPBadge(context.Background(), tt.opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRequestPoPBadge_ChallengePhase(t *testing.T) {
	// Generate test key
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use RawPath or RequestURI to check URL-encoded path
		// The DID "did:key:z6MkTest" is URL-encoded as "did%3Akey%3Az6MkTest"
		if r.URL.Path == "/v1/agents/did:key:z6MkTest/badge/challenge" {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "test-api-key", r.Header.Get("X-Capiscio-Registry-Key"))

			// Return challenge response
			resp := ChallengeResponse{
				ChallengeID: "test-challenge-id",
				Nonce:       "test-nonce-12345",
				ExpiresAt:   time.Now().Add(60 * time.Second),
				Aud:         "https://registry.capisc.io",
				HTU:         "https://registry.capisc.io/v1/agents/did%3Akey%3Az6MkTest/badge/pop",
				HTM:         "POST",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Handle PoP submission (Go decodes the path automatically)
		if r.URL.Path == "/v1/agents/did:key:z6MkTest/badge/pop" {
			assert.Equal(t, "POST", r.Method)
			
			// Return successful badge response
			resp := map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"token":           "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
					"jti":             "badge-123",
					"subject":         "did:key:z6MkTest",
					"trust_level":     "1",
					"assurance_level": "IAL-1",
					"expires_at":      time.Now().Add(5 * time.Minute).Format(time.RFC3339),
					"cnf": map[string]interface{}{
						"kid": "did:key:z6MkTest#z6MkTest",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		http.Error(w, "Not found", http.StatusNotFound)
	}))
	defer server.Close()

	client := NewPoPClient(server.URL, "test-api-key")

	result, err := client.RequestPoPBadge(context.Background(), RequestPoPBadgeOptions{
		AgentDID:   "did:key:z6MkTest",
		PrivateKey: privateKey,
		TTL:        5 * time.Minute,
		Audience:   []string{"https://api.example.com"},
	})

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "badge-123", result.JTI)
	assert.Equal(t, "did:key:z6MkTest", result.Subject)
	assert.Equal(t, "1", result.TrustLevel)
	assert.Equal(t, "IAL-1", result.AssuranceLevel)
}

func TestRequestPoPBadge_ChallengeError(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "AUTH_INVALID",
			"message": "Invalid API key",
		})
	}))
	defer server.Close()

	client := NewPoPClient(server.URL, "bad-key")

	_, err = client.RequestPoPBadge(context.Background(), RequestPoPBadgeOptions{
		AgentDID:   "did:key:z6MkTest",
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "challenge")
}

func TestRequestPoPBadge_ChallengeExpired(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return an already-expired challenge
		resp := ChallengeResponse{
			ChallengeID: "test-challenge-id",
			Nonce:       "test-nonce",
			ExpiresAt:   time.Now().Add(-10 * time.Second), // Expired 10 seconds ago
			Aud:         "https://registry.capisc.io",
			HTU:         "https://registry.capisc.io/v1/agents/did:key:z6MkTest/badge/pop",
			HTM:         "POST",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewPoPClient(server.URL, "test-key")

	_, err = client.RequestPoPBadge(context.Background(), RequestPoPBadgeOptions{
		AgentDID:   "did:key:z6MkTest",
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	clientErr, ok := err.(*ClientError)
	require.True(t, ok, "expected ClientError")
	assert.Equal(t, "CHALLENGE_EXPIRED", clientErr.Code)
}

func TestRequestPoPBadge_PoPError(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	callCount := 0
	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// Challenge succeeds
			resp := ChallengeResponse{
				ChallengeID: "test-challenge-id",
				Nonce:       "test-nonce",
				ExpiresAt:   time.Now().Add(60 * time.Second),
				Aud:         "https://registry.capisc.io",
				HTU:         serverURL + "/v1/agents/did:key:z6MkTest/badge/pop",
				HTM:         "POST",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// PoP fails
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "PROOF_INVALID",
			"message": "Invalid proof signature",
		})
	}))
	defer server.Close()
	serverURL = server.URL

	client := NewPoPClient(server.URL, "test-key")

	_, err = client.RequestPoPBadge(context.Background(), RequestPoPBadgeOptions{
		AgentDID:   "did:key:z6MkTest",
		PrivateKey: privateKey,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "pop")
}

func TestSignProof(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	client := NewPoPClient("https://example.com", "test-key")

	claims := PoPProofClaims{
		CID:   "challenge-123",
		Nonce: "nonce-456",
		Sub:   "did:key:z6MkTest",
		Aud:   "https://registry.capisc.io",
		HTU:   "https://registry.capisc.io/v1/agents/did%3Akey%3Az6MkTest/badge/pop",
		HTM:   "POST",
		IAT:   time.Now().Unix(),
		Exp:   time.Now().Add(60 * time.Second).Unix(),
		JTI:   "proof-jti-789",
	}

	jws, err := client.signProof(claims, privateKey, "did:key:z6MkTest")
	require.NoError(t, err)
	assert.NotEmpty(t, jws)

	// Verify it's a valid compact JWS (3 parts separated by dots)
	parts := 0
	for _, c := range jws {
		if c == '.' {
			parts++
		}
	}
	assert.Equal(t, 2, parts, "JWS should have 3 parts (2 dots)")
}

func TestSignProof_UnsupportedKeyType(t *testing.T) {
	client := NewPoPClient("https://example.com", "test-key")

	claims := PoPProofClaims{
		CID: "test",
	}

	// Pass a string instead of a valid key
	_, err := client.signProof(claims, "not-a-key", "did:key:z6MkTest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestParseErrorResponse(t *testing.T) {
	client := NewPoPClient("https://example.com", "test-key")

	tests := []struct {
		name       string
		statusCode int
		body       string
		phase      string
		wantCode   string
	}{
		{
			name:       "structured error",
			statusCode: http.StatusBadRequest,
			body:       `{"error": "INVALID_REQUEST", "message": "Bad request"}`,
			phase:      "challenge",
			wantCode:   "INVALID_REQUEST",
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			body:       `{}`,
			phase:      "challenge",
			wantCode:   "AUTH_INVALID",
		},
		{
			name:       "forbidden",
			statusCode: http.StatusForbidden,
			body:       `forbidden`,
			phase:      "pop",
			wantCode:   "FORBIDDEN",
		},
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			body:       `{}`,
			phase:      "challenge",
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "rate limited",
			statusCode: http.StatusTooManyRequests,
			body:       `{}`,
			phase:      "pop",
			wantCode:   "RATE_LIMITED",
		},
		{
			name:       "server error",
			statusCode: http.StatusInternalServerError,
			body:       `Internal error`,
			phase:      "challenge",
			wantCode:   "CA_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.parseErrorResponse(tt.statusCode, []byte(tt.body), tt.phase)
			require.Error(t, err)

			clientErr, ok := err.(*ClientError)
			require.True(t, ok, "expected ClientError")
			assert.Equal(t, tt.wantCode, clientErr.Code)
			assert.Contains(t, clientErr.Message, tt.phase)
		})
	}
}

func TestParsePoPResponse_Success(t *testing.T) {
	client := NewPoPClient("https://example.com", "test-key")

	body := `{
		"success": true,
		"data": {
			"token": "eyJhbGciOiJFZERTQSJ9...",
			"jti": "badge-456",
			"subject": "did:key:z6MkTest",
			"trust_level": "2",
			"assurance_level": "IAL-1",
			"expires_at": "2025-12-22T12:00:00Z",
			"cnf": {"kid": "did:key:z6MkTest#key-1"}
		}
	}`

	result, err := client.parsePoPResponse([]byte(body))
	require.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJFZERTQSJ9...", result.Token)
	assert.Equal(t, "badge-456", result.JTI)
	assert.Equal(t, "did:key:z6MkTest", result.Subject)
	assert.Equal(t, "2", result.TrustLevel)
	assert.Equal(t, "IAL-1", result.AssuranceLevel)
	assert.NotNil(t, result.CNF)
}

func TestParsePoPResponse_Failure(t *testing.T) {
	client := NewPoPClient("https://example.com", "test-key")

	body := `{
		"success": false,
		"error": "PROOF_EXPIRED"
	}`

	_, err := client.parsePoPResponse([]byte(body))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PROOF_EXPIRED")
}

func TestParsePoPResponse_InvalidJSON(t *testing.T) {
	client := NewPoPClient("https://example.com", "test-key")

	_, err := client.parsePoPResponse([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

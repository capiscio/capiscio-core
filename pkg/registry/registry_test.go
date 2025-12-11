package registry_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/pkg/registry"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalRegistry(t *testing.T) {
	// 1. Generate Key and Save to File
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{Key: pub, KeyID: "test-key", Algorithm: string(jose.EdDSA)}
	jwkBytes, _ := json.Marshal(jwk)

	tmpFile, err := os.CreateTemp("", "key-*.jwk")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(jwkBytes)
	require.NoError(t, err)
	tmpFile.Close()

	// 2. Test Registry
	reg := registry.NewLocalRegistry(tmpFile.Name())

	fetchedKey, err := reg.GetPublicKey(context.Background(), "any-issuer")
	require.NoError(t, err)
	assert.Equal(t, pub, fetchedKey)
}

func TestLocalRegistry_Caching(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := jose.JSONWebKey{Key: pub, KeyID: "test-key", Algorithm: string(jose.EdDSA)}
	jwkBytes, _ := json.Marshal(jwk)

	tmpFile, _ := os.CreateTemp("", "key-*.jwk")
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(jwkBytes)
	tmpFile.Close()

	reg := registry.NewLocalRegistry(tmpFile.Name())

	// First call loads from file
	key1, err := reg.GetPublicKey(context.Background(), "issuer1")
	require.NoError(t, err)

	// Second call uses cache (same key for any issuer)
	key2, err := reg.GetPublicKey(context.Background(), "issuer2")
	require.NoError(t, err)

	assert.Equal(t, key1, key2)
}

func TestLocalRegistry_FileNotFound(t *testing.T) {
	reg := registry.NewLocalRegistry("/nonexistent/path/key.jwk")
	_, err := reg.GetPublicKey(context.Background(), "issuer")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read local key file")
}

func TestLocalRegistry_InvalidJWK(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "invalid-*.jwk")
	defer os.Remove(tmpFile.Name())
	tmpFile.Write([]byte("not valid json"))
	tmpFile.Close()

	reg := registry.NewLocalRegistry(tmpFile.Name())
	_, err := reg.GetPublicKey(context.Background(), "issuer")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse local JWK")
}

func TestLocalRegistry_IsRevoked(t *testing.T) {
	reg := registry.NewLocalRegistry("")
	revoked, err := reg.IsRevoked(context.Background(), "any-id")
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestLocalRegistry_GetBadgeStatus(t *testing.T) {
	reg := registry.NewLocalRegistry("")
	_, err := reg.GetBadgeStatus(context.Background(), "http://example.com", "badge-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported in offline mode")
}

func TestLocalRegistry_GetAgentStatus(t *testing.T) {
	reg := registry.NewLocalRegistry("")
	_, err := reg.GetAgentStatus(context.Background(), "http://example.com", "agent-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported in offline mode")
}

func TestLocalRegistry_SyncRevocations(t *testing.T) {
	reg := registry.NewLocalRegistry("")
	_, err := reg.SyncRevocations(context.Background(), "http://example.com", time.Now())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported in offline mode")
}

func TestCloudRegistry(t *testing.T) {
	// 1. Setup Mock Server
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: pub, KeyID: "cloud-key", Algorithm: string(jose.EdDSA)}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwk)
	}))
	defer server.Close()

	// 2. Test Registry
	reg := registry.NewCloudRegistry(server.URL)

	fetchedKey, err := reg.GetPublicKey(context.Background(), "any-issuer")
	require.NoError(t, err)
	assert.Equal(t, pub, fetchedKey)

	// 3. Test Cache (Stop Server and fetch again)
	server.Close()
	// Note: In a real test we might want to verify no network call is made,
	// but here we rely on the fact that if cache failed, this would error out
	// because the server is closed.
	cachedKey, err := reg.GetPublicKey(context.Background(), "any-issuer")
	require.NoError(t, err)
	assert.Equal(t, pub, cachedKey)
}

func TestCloudRegistry_IsRevoked(t *testing.T) {
	reg := registry.NewCloudRegistry("http://example.com")
	revoked, err := reg.IsRevoked(context.Background(), "any-id")
	assert.NoError(t, err)
	assert.False(t, revoked)
}

func TestCloudRegistry_GetPublicKey_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	reg := registry.NewCloudRegistry(server.URL)
	_, err := reg.GetPublicKey(context.Background(), "issuer")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestCloudRegistry_GetPublicKey_InvalidJWK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	reg := registry.NewCloudRegistry(server.URL)
	_, err := reg.GetPublicKey(context.Background(), "issuer")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode JWK")
}

func TestCloudRegistry_GetBadgeStatus(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/badges/badge-123/status", r.URL.Path)
			json.NewEncoder(w).Encode(registry.BadgeStatus{
				JTI:     "badge-123",
				Subject: "agent-1",
				Revoked: false,
			})
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		status, err := reg.GetBadgeStatus(context.Background(), server.URL, "badge-123")
		require.NoError(t, err)
		assert.Equal(t, "badge-123", status.JTI)
		assert.False(t, status.Revoked)
	})

	t.Run("NotFound", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.GetBadgeStatus(context.Background(), server.URL, "missing")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "badge not found")
	})

	t.Run("ServerError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.GetBadgeStatus(context.Background(), server.URL, "badge")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 502")
	})

	t.Run("InvalidResponse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.GetBadgeStatus(context.Background(), server.URL, "badge")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode badge status")
	})
}

func TestCloudRegistry_GetAgentStatus(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/agents/agent-123/status", r.URL.Path)
			json.NewEncoder(w).Encode(registry.AgentStatus{
				Status: "active",
			})
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		status, err := reg.GetAgentStatus(context.Background(), server.URL, "agent-123")
		require.NoError(t, err)
		assert.Equal(t, "active", status.Status)
	})

	t.Run("NotFound", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.GetAgentStatus(context.Background(), server.URL, "missing")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "agent not found")
	})

	t.Run("ServerError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.GetAgentStatus(context.Background(), server.URL, "agent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 503")
	})

	t.Run("InvalidResponse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.GetAgentStatus(context.Background(), server.URL, "agent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode agent status")
	})
}

func TestCloudRegistry_SyncRevocations(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		now := time.Now()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Contains(t, r.URL.Path, "/v1/revocations")
			assert.NotEmpty(t, r.URL.Query().Get("since"))
			json.NewEncoder(w).Encode(map[string]interface{}{
				"revocations": []registry.Revocation{
					{JTI: "badge-1", RevokedAt: now, Reason: "compromised"},
					{JTI: "badge-2", RevokedAt: now, Reason: "expired"},
				},
			})
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		revocations, err := reg.SyncRevocations(context.Background(), server.URL, time.Now().Add(-24*time.Hour))
		require.NoError(t, err)
		assert.Len(t, revocations, 2)
		assert.Equal(t, "badge-1", revocations[0].JTI)
	})

	t.Run("ServerError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.SyncRevocations(context.Background(), server.URL, time.Now())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status 500")
	})

	t.Run("InvalidResponse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		_, err := reg.SyncRevocations(context.Background(), server.URL, time.Now())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode revocations")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"revocations": []registry.Revocation{},
			})
		}))
		defer server.Close()

		reg := registry.NewCloudRegistry("")
		revocations, err := reg.SyncRevocations(context.Background(), server.URL, time.Now())
		require.NoError(t, err)
		assert.Empty(t, revocations)
	})
}

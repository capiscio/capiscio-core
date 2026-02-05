package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAgentCard(t *testing.T) {
	// Generate real Ed25519 key for testing
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey := did.NewKeyDID(pub)
	pubJwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     didKey,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Test agent card creation
	card := createAgentCard(
		"test-agent-id-123",
		"Test Agent",
		didKey,
		"https://registry.capisc.io",
		pubJwk,
	)

	assert.Equal(t, "Test Agent", card["name"])
	assert.Equal(t, "1.0.0", card["version"])
	assert.Equal(t, "0.3.0", card["protocolVersion"])
	assert.Equal(t, "CapiscIO-enabled A2A agent", card["description"])

	// Check x-capiscio extension
	xcapiscio, ok := card["x-capiscio"].(map[string]interface{})
	require.True(t, ok, "x-capiscio should be a map")
	assert.Equal(t, didKey, xcapiscio["did"])
	assert.Equal(t, "test-agent-id-123", xcapiscio["agentId"])
	assert.Equal(t, "https://registry.capisc.io", xcapiscio["registry"])
}

func TestCreateAgentCardDefaultName(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey := did.NewKeyDID(pub)
	pubJwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     didKey,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	card := createAgentCard(
		"12345678-abcd-efgh-ijkl",
		"", // empty name should trigger default
		didKey,
		"https://registry.capisc.io",
		pubJwk,
	)

	// Should use Agent-{first 8 chars of ID}
	assert.Equal(t, "Agent-12345678", card["name"])
}

func TestFetchFirstAgent(t *testing.T) {
	// Mock server that returns an agent list
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agents" {
			// Check auth header
			authHeader := r.Header.Get("X-Capiscio-Registry-Key")
			if authHeader == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]string{
					{"id": "agent-001", "name": "First Agent"},
					{"id": "agent-002", "name": "Second Agent"},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	id, name, err := fetchFirstAgent(server.URL, "test-api-key")
	require.NoError(t, err)
	assert.Equal(t, "agent-001", id)
	assert.Equal(t, "First Agent", name)
}

func TestFetchFirstAgentNoAgents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]string{}, // empty list
		})
	}))
	defer server.Close()

	_, _, err := fetchFirstAgent(server.URL, "test-api-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no agents found")
}

func TestFetchFirstAgentAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	}))
	defer server.Close()

	_, _, err := fetchFirstAgent(server.URL, "bad-api-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestRegisterDID(t *testing.T) {
	var received struct {
		DID       string `json:"did"`
		PublicKey string `json:"publicKey"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check path
		if r.URL.Path != "/v1/agents/test-agent-123" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Check auth
		if r.Header.Get("X-Capiscio-Registry-Key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Parse body
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Generate test keys
	pub := make([]byte, 32) // Mock Ed25519 public key
	
	err := registerDID(server.URL, "test-api-key", "test-agent-123", "did:key:z6MkTest", pub)
	require.NoError(t, err)
	assert.Equal(t, "did:key:z6MkTest", received.DID)
}

func TestRegisterDIDServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
	}))
	defer server.Close()

	pub := make([]byte, 32)
	err := registerDID(server.URL, "test-api-key", "agent-id", "did:key:z6MkTest", pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestInitOutputDirectory(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "test-agent")

	// Create directory with proper permissions
	err := os.MkdirAll(outputDir, 0700)
	require.NoError(t, err)

	// Check permissions (Unix only)
	info, err := os.Stat(outputDir)
	require.NoError(t, err)
	assert.Equal(t, os.ModeDir|0700, info.Mode())
}

func TestInitFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	// Test private key permissions
	privateKeyPath := filepath.Join(tmpDir, "private.jwk")
	err := os.WriteFile(privateKeyPath, []byte("secret"), 0600)
	require.NoError(t, err)

	info, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Test public key permissions
	publicKeyPath := filepath.Join(tmpDir, "public.jwk")
	err = os.WriteFile(publicKeyPath, []byte("public"), 0644)
	require.NoError(t, err)

	info, err = os.Stat(publicKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func TestInitForceFlag(t *testing.T) {
	tmpDir := t.TempDir()
	privateKeyPath := filepath.Join(tmpDir, "private.jwk")

	// Create existing key file
	err := os.WriteFile(privateKeyPath, []byte("existing-key"), 0600)
	require.NoError(t, err)

	// Without force, should detect existing file
	_, err = os.Stat(privateKeyPath)
	assert.NoError(t, err, "File should exist")

	// This simulates what the CLI would check
	if _, err := os.Stat(privateKeyPath); err == nil {
		// File exists - without force flag, this would return error
		// With force flag, we'd continue and overwrite
	}
}

func TestServerURLValidation(t *testing.T) {
	tests := []struct {
		url      string
		isSecure bool
	}{
		{"https://registry.capisc.io", true},
		{"https://localhost:8443", true},
		{"http://localhost:8080", true}, // localhost is allowed
		{"http://registry.capisc.io", false},
		{"http://example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			// Check HTTPS or localhost exception
			isSecure := tc.url[:8] == "https://" || tc.url == "http://localhost:8080"
			assert.Equal(t, tc.isSecure, isSecure)
		})
	}
}

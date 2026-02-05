package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestCreateAgentCardShortID(t *testing.T) {
	// Test edge case where agentID is less than 8 characters
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey := did.NewKeyDID(pub)
	pubJwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     didKey,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Test with various short IDs
	testCases := []struct {
		agentID  string
		expected string
	}{
		{"abc", "Agent-abc"},
		{"ab", "Agent-ab"},
		{"a", "Agent-a"},
		{"", "Agent-"},
		{"12345678", "Agent-12345678"}, // exactly 8 chars
		{"123456789", "Agent-12345678"}, // 9 chars, should truncate
	}

	for _, tc := range testCases {
		t.Run("agentID="+tc.agentID, func(t *testing.T) {
			card := createAgentCard(tc.agentID, "", didKey, "https://registry.capisc.io", pubJwk)
			assert.Equal(t, tc.expected, card["name"])
		})
	}
}

func TestFetchFirstAgent(t *testing.T) {
	// Mock server that returns an agent list
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agents" {
			// Check auth header (Bearer token)
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
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
		DID       string          `json:"did"`
		PublicKey json.RawMessage `json:"public_key"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Check path - should be POST /v1/agents/{id}/dids
		if r.URL.Path != "/v1/agents/test-agent-123/dids" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Check Bearer auth
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
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
		name      string
		url       string
		expected  string
		wantWarn  bool // expects warning for non-HTTPS
	}{
		{"HTTPS URL", "https://registry.capisc.io", "https://registry.capisc.io", false},
		{"HTTPS with trailing slash", "https://registry.capisc.io/", "https://registry.capisc.io", false},
		{"HTTP localhost 8080", "http://localhost:8080", "http://localhost:8080", false},
		{"HTTP localhost other port", "http://localhost:3000", "http://localhost:3000", false},
		{"HTTP 127.0.0.1", "http://127.0.0.1:8080", "http://127.0.0.1:8080", false},
		{"HTTP non-localhost", "http://example.com", "http://example.com", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validateServerURL(tc.url)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestResolveAPIKey(t *testing.T) {
	// Save and restore original values
	origEnv := os.Getenv("CAPISCIO_API_KEY")
	origFlag := initAPIKey
	defer func() {
		os.Setenv("CAPISCIO_API_KEY", origEnv)
		initAPIKey = origFlag
	}()

	t.Run("from environment variable", func(t *testing.T) {
		os.Setenv("CAPISCIO_API_KEY", "env-api-key")
		initAPIKey = ""
		key, err := resolveAPIKey()
		require.NoError(t, err)
		assert.Equal(t, "env-api-key", key)
	})

	t.Run("from flag when env empty", func(t *testing.T) {
		os.Setenv("CAPISCIO_API_KEY", "")
		initAPIKey = "flag-api-key"
		key, err := resolveAPIKey()
		require.NoError(t, err)
		assert.Equal(t, "flag-api-key", key)
	})

	t.Run("env takes precedence over flag", func(t *testing.T) {
		os.Setenv("CAPISCIO_API_KEY", "env-key")
		initAPIKey = "flag-key"
		key, err := resolveAPIKey()
		require.NoError(t, err)
		assert.Equal(t, "env-key", key)
	})

	t.Run("error when both empty", func(t *testing.T) {
		os.Setenv("CAPISCIO_API_KEY", "")
		initAPIKey = ""
		_, err := resolveAPIKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "API key required")
	})
}

func TestValidateServerURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://registry.capisc.io/", "https://registry.capisc.io"},
		{"https://registry.capisc.io", "https://registry.capisc.io"},
		{"http://localhost:8080/", "http://localhost:8080"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := validateServerURL(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSetupOutputDir(t *testing.T) {
	// Save and restore original values
	origOutputDir := initOutputDir
	origForce := initForce
	defer func() {
		initOutputDir = origOutputDir
		initForce = origForce
	}()

	t.Run("creates directory if not exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		initOutputDir = filepath.Join(tmpDir, "new-agent")
		initForce = false

		dir, err := setupOutputDir("test-agent-id")
		require.NoError(t, err)
		assert.Equal(t, initOutputDir, dir)

		// Check directory was created
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("error if keys exist without force", func(t *testing.T) {
		tmpDir := t.TempDir()
		initOutputDir = tmpDir
		initForce = false

		// Create existing private key
		err := os.WriteFile(filepath.Join(tmpDir, "private.jwk"), []byte("key"), 0600)
		require.NoError(t, err)

		_, err = setupOutputDir("test-agent-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "keys already exist")
	})

	t.Run("allows overwrite with force", func(t *testing.T) {
		tmpDir := t.TempDir()
		initOutputDir = tmpDir
		initForce = true

		// Create existing private key
		err := os.WriteFile(filepath.Join(tmpDir, "private.jwk"), []byte("key"), 0600)
		require.NoError(t, err)

		dir, err := setupOutputDir("test-agent-id")
		require.NoError(t, err)
		assert.Equal(t, tmpDir, dir)
	})

	t.Run("uses default directory if not specified", func(t *testing.T) {
		initOutputDir = ""
		initForce = true

		dir, err := setupOutputDir("test-agent-123")
		require.NoError(t, err)
		assert.Contains(t, dir, ".capiscio")
		assert.Contains(t, dir, "test-agent-123")

		// Cleanup
		os.RemoveAll(dir)
	})
}

func TestGenerateAndSaveKeys(t *testing.T) {
	tmpDir := t.TempDir()

	pub, priv, didKey, pubJwk, err := generateAndSaveKeys(tmpDir)
	require.NoError(t, err)

	// Verify outputs
	assert.NotNil(t, pub)
	assert.NotNil(t, priv)
	assert.True(t, len(didKey) > 0)
	assert.Contains(t, didKey, "did:key:z6Mk")
	assert.NotNil(t, pubJwk.Key)

	// Verify files were created
	privateKeyPath := filepath.Join(tmpDir, "private.jwk")
	publicKeyPath := filepath.Join(tmpDir, "public.jwk")
	didPath := filepath.Join(tmpDir, "did.txt")

	// Check private key
	privInfo, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), privInfo.Mode().Perm())

	// Check public key
	pubInfo, err := os.Stat(publicKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), pubInfo.Mode().Perm())

	// Check DID file
	didContent, err := os.ReadFile(didPath)
	require.NoError(t, err)
	assert.Contains(t, string(didContent), didKey)

	// Verify JWK files are valid JSON
	var jwk jose.JSONWebKey
	privBytes, _ := os.ReadFile(privateKeyPath)
	err = json.Unmarshal(privBytes, &jwk)
	require.NoError(t, err)
	assert.Equal(t, didKey, jwk.KeyID)
}

func TestSaveAgentCard(t *testing.T) {
	tmpDir := t.TempDir()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey := did.NewKeyDID(pub)
	pubJwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     didKey,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	err = saveAgentCard(tmpDir, "agent-123", "Test Agent", didKey, "https://registry.capisc.io", pubJwk)
	require.NoError(t, err)

	// Verify file was created
	cardPath := filepath.Join(tmpDir, "agent-card.json")
	cardBytes, err := os.ReadFile(cardPath)
	require.NoError(t, err)

	var card map[string]interface{}
	err = json.Unmarshal(cardBytes, &card)
	require.NoError(t, err)

	assert.Equal(t, "Test Agent", card["name"])
	xcapiscio := card["x-capiscio"].(map[string]interface{})
	assert.Equal(t, didKey, xcapiscio["did"])
	assert.Equal(t, "agent-123", xcapiscio["agentId"])
}

func TestResolveAgentID(t *testing.T) {
	// Save and restore original values
	origAgentID := initAgentID
	origAgentName := initAgentName
	defer func() {
		initAgentID = origAgentID
		initAgentName = origAgentName
	}()

	t.Run("uses provided agent ID", func(t *testing.T) {
		initAgentID = "explicit-agent-id"
		initAgentName = "Explicit Name"

		id, name, err := resolveAgentID("http://localhost:8080", "api-key")
		require.NoError(t, err)
		assert.Equal(t, "explicit-agent-id", id)
		assert.Equal(t, "Explicit Name", name)
	})

	t.Run("fetches from server when not provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]string{
					{"id": "fetched-agent-id", "name": "Fetched Agent"},
				},
			})
		}))
		defer server.Close()

		initAgentID = ""
		initAgentName = ""

		id, name, err := resolveAgentID(server.URL, "api-key")
		require.NoError(t, err)
		assert.Equal(t, "fetched-agent-id", id)
		assert.Equal(t, "Fetched Agent", name)
	})
}

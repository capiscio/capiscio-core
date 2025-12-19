package did_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDomain  string
		wantAgentID string
		wantPath    []string
		wantErr     error
	}{
		{
			name:        "valid agent DID",
			input:       "did:web:registry.capisc.io:agents:my-agent-001",
			wantDomain:  "registry.capisc.io",
			wantAgentID: "my-agent-001",
			wantPath:    []string{"agents", "my-agent-001"},
		},
		{
			name:        "valid agent DID with custom domain",
			input:       "did:web:example.com:agents:test-agent",
			wantDomain:  "example.com",
			wantAgentID: "test-agent",
			wantPath:    []string{"agents", "test-agent"},
		},
		{
			name:        "DID with no path (domain only)",
			input:       "did:web:example.com",
			wantDomain:  "example.com",
			wantAgentID: "",
			wantPath:    []string{},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: did.ErrInvalidDID,
		},
		{
			name:    "invalid prefix",
			input:   "did:ethr:0x123",
			wantErr: did.ErrUnsupportedMethod,
		},
		{
			name:    "too short",
			input:   "did:web",
			wantErr: did.ErrInvalidDID,
		},
		{
			name:    "not a DID",
			input:   "https://example.com",
			wantErr: did.ErrInvalidDID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, "web", parsed.Method)
			assert.Equal(t, tc.wantDomain, parsed.Domain)
			assert.Equal(t, tc.wantAgentID, parsed.AgentID)
			assert.Equal(t, tc.wantPath, parsed.PathSegments)
			assert.Equal(t, tc.input, parsed.Raw)
		})
	}
}

func TestDID_DocumentURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantURL string
	}{
		{
			name:    "agent DID",
			input:   "did:web:registry.capisc.io:agents:my-agent-001",
			wantURL: "https://registry.capisc.io/agents/my-agent-001/did.json",
		},
		{
			name:    "domain only",
			input:   "did:web:example.com",
			wantURL: "https://example.com/did.json",
		},
		{
			name:    "nested path",
			input:   "did:web:example.com:foo:bar:baz",
			wantURL: "https://example.com/foo/bar/baz/did.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.wantURL, parsed.DocumentURL())
		})
	}
}

func TestDID_String(t *testing.T) {
	input := "did:web:registry.capisc.io:agents:test-agent"
	parsed, err := did.Parse(input)
	require.NoError(t, err)
	assert.Equal(t, input, parsed.String())
}

func TestNewAgentDID(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		agentID  string
		expected string
	}{
		{
			name:     "standard domain",
			domain:   "registry.capisc.io",
			agentID:  "my-agent-001",
			expected: "did:web:registry.capisc.io:agents:my-agent-001",
		},
		{
			name:     "custom domain",
			domain:   "my-company.com",
			agentID:  "production-agent",
			expected: "did:web:my-company.com:agents:production-agent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := did.NewAgentDID(tc.domain, tc.agentID)
			assert.Equal(t, tc.expected, result)

			// Verify it can be parsed back
			parsed, err := did.Parse(result)
			require.NoError(t, err)
			assert.Equal(t, tc.domain, parsed.Domain)
			assert.Equal(t, tc.agentID, parsed.AgentID)
		})
	}
}

func TestNewCapiscIOAgentDID(t *testing.T) {
	result := did.NewCapiscIOAgentDID("my-agent")
	assert.Equal(t, "did:web:registry.capisc.io:agents:my-agent", result)
}

func TestDID_IsAgentDID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid agent DID",
			input: "did:web:registry.capisc.io:agents:my-agent",
			want:  true,
		},
		{
			name:  "domain only",
			input: "did:web:example.com",
			want:  false,
		},
		{
			name:  "different path",
			input: "did:web:example.com:users:alice",
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, parsed.IsAgentDID())
		})
	}
}

// ============================================================================
// did:key Tests (RFC-002 v1.1 §6.6)
// ============================================================================

func TestParse_DidKey(t *testing.T) {
	// Test vector from W3C did:key spec
	// Ed25519 public key: 0x... (32 bytes)
	// did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

	tests := []struct {
		name          string
		input         string
		wantMethod    string
		wantKeyLen    int
		wantErr       error
		wantErrString string
	}{
		{
			name:       "valid did:key (W3C test vector)",
			input:      "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			wantMethod: "key",
			wantKeyLen: 32,
		},
		{
			name:          "did:key with invalid multibase prefix",
			input:         "did:key:m6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			wantErr:       did.ErrInvalidKeyDID,
			wantErrString: "expected 'z' (base58btc) prefix",
		},
		{
			name:          "did:key empty identifier",
			input:         "did:key:",
			wantErr:       did.ErrInvalidKeyDID,
			wantErrString: "empty key identifier",
		},
		{
			name:          "did:key too many parts",
			input:         "did:key:z6Mk:extra",
			wantErr:       did.ErrInvalidKeyDID,
			wantErrString: "must have exactly 3 parts",
		},
		{
			name:          "did:key invalid base58 character",
			input:         "did:key:z0OIl", // 0, O, I, l are not in base58
			wantErr:       did.ErrInvalidKeyDID,
			wantErrString: "invalid base58",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				if tc.wantErrString != "" {
					assert.Contains(t, err.Error(), tc.wantErrString)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantMethod, parsed.Method)
			assert.Equal(t, tc.wantKeyLen, len(parsed.PublicKey))
			assert.Equal(t, tc.input, parsed.Raw)
			assert.True(t, parsed.IsKeyDID())
			assert.False(t, parsed.IsWebDID())
		})
	}
}

func TestNewKeyDID(t *testing.T) {
	// Generate a test keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create did:key
	didStr := did.NewKeyDID(pub)

	// Should start with did:key:z
	assert.True(t, len(didStr) > 0)
	assert.True(t, didStr[:10] == "did:key:z6", "did:key should start with 'did:key:z6' for Ed25519, got: %s", didStr[:15])

	// Should be parseable
	parsed, err := did.Parse(didStr)
	require.NoError(t, err)

	// Should round-trip the public key
	assert.Equal(t, []byte(pub), parsed.PublicKey)
	assert.Equal(t, "key", parsed.Method)
}

func TestNewKeyDID_InvalidSize(t *testing.T) {
	// Wrong size key should return empty string
	result := did.NewKeyDID([]byte{1, 2, 3}) // Too short
	assert.Equal(t, "", result)

	result = did.NewKeyDID(make([]byte, 64)) // Too long
	assert.Equal(t, "", result)
}

func TestPublicKeyFromKeyDID(t *testing.T) {
	// Generate a test keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create did:key and extract public key
	didStr := did.NewKeyDID(pub)
	extracted, err := did.PublicKeyFromKeyDID(didStr)
	require.NoError(t, err)

	// Should match original
	assert.Equal(t, pub, extracted)
}

func TestPublicKeyFromKeyDID_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:    "did:web not allowed",
			input:   "did:web:example.com",
			wantErr: did.ErrInvalidKeyDID,
		},
		{
			name:    "invalid DID format",
			input:   "not-a-did",
			wantErr: did.ErrInvalidDID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := did.PublicKeyFromKeyDID(tc.input)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestDID_IsKeyDID_IsWebDID(t *testing.T) {
	// did:web
	webDID, err := did.Parse("did:web:example.com:agents:test")
	require.NoError(t, err)
	assert.True(t, webDID.IsWebDID())
	assert.False(t, webDID.IsKeyDID())

	// did:key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyDIDStr := did.NewKeyDID(pub)

	keyDID, err := did.Parse(keyDIDStr)
	require.NoError(t, err)
	assert.True(t, keyDID.IsKeyDID())
	assert.False(t, keyDID.IsWebDID())
}

func TestDID_GetPublicKey(t *testing.T) {
	// Generate keypair
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create and parse did:key
	keyDID, err := did.Parse(did.NewKeyDID(pub))
	require.NoError(t, err)

	// GetPublicKey should return the key
	gotKey := keyDID.GetPublicKey()
	require.NotNil(t, gotKey)
	assert.Equal(t, pub, gotKey)

	// did:web should return nil
	webDID, err := did.Parse("did:web:example.com")
	require.NoError(t, err)
	assert.Nil(t, webDID.GetPublicKey())
}

func TestDID_DocumentURL_ForKeyDID(t *testing.T) {
	// did:key doesn't have a remote document
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyDID, err := did.Parse(did.NewKeyDID(pub))
	require.NoError(t, err)

	// Should return empty string
	assert.Equal(t, "", keyDID.DocumentURL())
}

func TestNewKeyDID_KnownVector(t *testing.T) {
	// Known test vector: 32 zero bytes should produce a deterministic did:key
	zeroKey := make([]byte, 32)
	result := did.NewKeyDID(zeroKey)

	// Parse it back
	parsed, err := did.Parse(result)
	require.NoError(t, err)
	assert.Equal(t, zeroKey, parsed.PublicKey)

	// Verify it starts correctly
	assert.True(t, len(result) > 10)
	assert.Equal(t, "did:key:z", result[:9])
}

func TestBase58_RoundTrip(t *testing.T) {
	// Test that our base58 implementation correctly round-trips
	testCases := [][]byte{
		{},
		{0},
		{0, 0, 0},
		{1, 2, 3, 4, 5},
		make([]byte, 32), // 32 zero bytes
	}

	// Generate random 32-byte values
	for i := 0; i < 5; i++ {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		testCases = append(testCases, b)
	}

	for i, tc := range testCases {
		t.Run(hex.EncodeToString(tc), func(t *testing.T) {
			// Create did:key with prefixed data
			prefixed := make([]byte, 2+len(tc))
			prefixed[0] = 0xed
			prefixed[1] = 0x01
			copy(prefixed[2:], tc)

			// Can only test 32-byte keys properly through NewKeyDID
			if len(tc) == 32 {
				didStr := did.NewKeyDID(tc)
				parsed, err := did.Parse(didStr)
				require.NoError(t, err, "test case %d", i)
				assert.Equal(t, tc, parsed.PublicKey, "test case %d", i)
			}
		})
	}
}

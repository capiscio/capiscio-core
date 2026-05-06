package did

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a test Ed25519 key pair and build a DID document.
func testKeyAndDocument(t *testing.T, didStr string, kid string) (ed25519.PublicKey, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	vmID := didStr + "#" + kid
	doc := Document{
		ID: didStr,
		VerificationMethod: []VerificationMethod{
			{
				ID:         vmID,
				Type:       "JsonWebKey2020",
				Controller: didStr,
				PublicKeyJwk: &JWK{
					Kty: "OKP",
					Crv: "Ed25519",
					X:   base64.RawURLEncoding.EncodeToString(pub),
				},
			},
		},
	}
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)
	return pub, priv, docBytes
}

func TestWebResolver_BasicResolve(t *testing.T) {
	// Setup test server
	didStr := "did:web:example.com"
	kid := "key-0"
	pub, _, docBytes := testKeyAndDocument(t, didStr, kid)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/did+json")
		w.Write(docBytes)
	}))
	defer server.Close()

	resolver := &WebResolver{
		Client:    server.Client(),
		AllowHTTP: true, // test server uses HTTP
		CacheTTL:  time.Minute,
	}
	resolver.initOnce.Do(resolver.init)

	// Override document URL by testing with a DID that points to our test server
	// We'll directly test resolveDocument with the test server URL
	ctx := context.Background()
	doc, err := resolver.resolveDocument(ctx, server.URL+"/.well-known/did.json")
	require.NoError(t, err)
	assert.Equal(t, didStr, doc.ID)

	// Extract key
	key, err := resolver.extractKey(doc, didStr, kid)
	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), key)
}

func TestWebResolver_PathSegments(t *testing.T) {
	// did:web:example.com:agents:worker → https://example.com/agents/worker/did.json
	parsed, err := Parse("did:web:example.com:agents:worker")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/agents/worker/did.json", parsed.DocumentURL())
}

func TestWebResolver_KeyIDFragmentMatching(t *testing.T) {
	didStr := "did:web:example.com"
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)

	doc := &Document{
		ID: didStr,
		VerificationMethod: []VerificationMethod{
			{
				ID:   didStr + "#key-0",
				Type: "JsonWebKey2020",
				PublicKeyJwk: &JWK{
					Kty: "OKP", Crv: "Ed25519",
					X: base64.RawURLEncoding.EncodeToString(pub1),
				},
			},
			{
				ID:   didStr + "#key-1",
				Type: "JsonWebKey2020",
				PublicKeyJwk: &JWK{
					Kty: "OKP", Crv: "Ed25519",
					X: base64.RawURLEncoding.EncodeToString(pub2),
				},
			},
		},
	}

	resolver := &WebResolver{}

	// Should match key-0
	key, err := resolver.extractKey(doc, didStr, "key-0")
	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub1), key)

	// Should match key-1
	key, err = resolver.extractKey(doc, didStr, "key-1")
	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub2), key)

	// Non-existent key → error
	_, err = resolver.extractKey(doc, didStr, "key-99")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestWebResolver_SSRF_Localhost(t *testing.T) {
	resolver := &WebResolver{
		CacheTTL: time.Minute,
	}

	ctx := context.Background()
	_, err := resolver.Resolve(ctx, "did:web:localhost", "key-0")
	assert.Error(t, err)
	// Should fail with HTTPS requirement (localhost → http://)
	assert.True(t, strings.Contains(err.Error(), "HTTPS") || strings.Contains(err.Error(), "SSRF"),
		"expected HTTPS or SSRF error, got: %v", err)
}

func TestWebResolver_SSRF_PrivateIP(t *testing.T) {
	// Test that private IPs are blocked by the dialer
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse IP %q", tt.ip)
			assert.Equal(t, tt.want, isPrivateIP(ip), "isPrivateIP(%s)", tt.ip)
		})
	}
}

func TestWebResolver_SSRF_BlockedHostname(t *testing.T) {
	resolver := &WebResolver{
		AllowHTTP: true,
		CacheTTL:  time.Minute,
	}
	resolver.initOnce.Do(resolver.init)

	// The SSRF dialer should block connections to metadata endpoints
	ctx := context.Background()

	// Test internal resolution for 127.0.0.1 via the dialer
	dialFn := ssrfSafeDialer()
	_, err := dialFn(ctx, "tcp", "localhost:443")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSSRFBlocked)

	_, err = dialFn(ctx, "tcp", "metadata.google.internal:80")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSSRFBlocked)

	_ = resolver // silence unused
}

func TestWebResolver_OversizedDocument(t *testing.T) {
	// Server returns a document larger than MaxDocSize
	bigBody := strings.Repeat("x", 100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(bigBody))
	}))
	defer server.Close()

	resolver := &WebResolver{
		Client:     server.Client(),
		AllowHTTP:  true,
		MaxDocSize: 50, // Very small limit for testing
		CacheTTL:   time.Minute,
	}
	resolver.initOnce.Do(resolver.init)

	ctx := context.Background()
	_, err := resolver.resolveDocument(ctx, server.URL+"/.well-known/did.json")
	assert.ErrorIs(t, err, ErrDocumentTooLarge)
}

func TestWebResolver_TimeoutEnforcement(t *testing.T) {
	// Server that never responds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	resolver := &WebResolver{
		Client: &http.Client{
			Timeout: 50 * time.Millisecond,
		},
		AllowHTTP: true,
		CacheTTL:  time.Minute,
	}
	resolver.initOnce.Do(resolver.init)

	ctx := context.Background()
	_, err := resolver.resolveDocument(ctx, server.URL+"/.well-known/did.json")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDocumentFetch)
}

func TestWebResolver_CacheHit(t *testing.T) {
	didStr := "did:web:example.com"
	kid := "key-0"
	_, _, docBytes := testKeyAndDocument(t, didStr, kid)

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Write(docBytes)
	}))
	defer server.Close()

	resolver := &WebResolver{
		Client:    server.Client(),
		AllowHTTP: true,
		CacheTTL:  time.Minute,
	}
	resolver.initOnce.Do(resolver.init)

	ctx := context.Background()
	url := server.URL + "/.well-known/did.json"

	// First call → HTTP request
	_, err := resolver.resolveDocument(ctx, url)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call → cache hit, no HTTP request
	_, err = resolver.resolveDocument(ctx, url)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "expected cache hit, but got another HTTP request")
}

func TestWebResolver_MultibaseKey(t *testing.T) {
	// Test Ed25519VerificationKey2020 with publicKeyMultibase
	pub, _, _ := ed25519.GenerateKey(nil)

	// Build multibase encoded key: 'z' + base58btc(0xed01 || pubkey)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	multibase := "z" + base58Encode(prefixed)

	doc := &Document{
		ID: "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:                 "did:web:example.com#key-0",
				Type:               "Ed25519VerificationKey2020",
				PublicKeyMultibase: multibase,
			},
		},
	}

	resolver := &WebResolver{}
	key, err := resolver.extractKey(doc, "did:web:example.com", "key-0")
	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), key)
}

func TestWebResolver_JWK_InvalidCurve(t *testing.T) {
	doc := &Document{
		ID: "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:   "did:web:example.com#key-0",
				Type: "JsonWebKey2020",
				PublicKeyJwk: &JWK{
					Kty: "EC",
					Crv: "P-256",
					X:   "invalid",
				},
			},
		},
	}

	resolver := &WebResolver{}
	_, err := resolver.extractKey(doc, "did:web:example.com", "key-0")
	assert.ErrorIs(t, err, ErrUnsupportedVMType)
}

func TestDecodeJWK_Valid(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	jwk := &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}

	key, err := decodeJWK(jwk)
	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), key)
}

func TestDecodeJWK_WrongSize(t *testing.T) {
	jwk := &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString([]byte("too-short")),
	}

	_, err := decodeJWK(jwk)
	assert.ErrorIs(t, err, ErrUnsupportedVMType)
}

func TestWebResolver_HTTPSRequired(t *testing.T) {
	resolver := &WebResolver{
		AllowHTTP: false, // Production mode
		CacheTTL:  time.Minute,
	}

	ctx := context.Background()
	// did:web:127.0.0.1 → http://127.0.0.1/.well-known/did.json (because DocumentURL uses HTTP for localhost/127)
	_, err := resolver.Resolve(ctx, "did:web:127.0.0.1", "key-0")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHTTPRequired)
}

func TestNewCompositeKeyResolver(t *testing.T) {
	// Integration test: composite resolver handles did:key locally
	pub, _, _ := ed25519.GenerateKey(nil)
	didKeyStr := NewKeyDID(pub)

	resolver := &WebResolver{CacheTTL: time.Minute}
	compositeResolver := NewCompositeKeyResolver(resolver)

	ctx := context.Background()
	key, err := compositeResolver(ctx, didKeyStr, "")
	require.NoError(t, err)
	assert.Equal(t, ed25519.PublicKey(pub), key)
}

// NewCompositeKeyResolver is in pkg/envelope - test the integration pattern
func NewCompositeKeyResolver(webResolver *WebResolver) func(ctx context.Context, didStr string, kid string) (interface{}, error) {
	return func(ctx context.Context, didStr string, kid string) (interface{}, error) {
		parsed, err := Parse(didStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DID %q: %w", didStr, err)
		}
		if parsed.IsKeyDID() {
			pubKey := parsed.GetPublicKey()
			if pubKey == nil {
				return nil, fmt.Errorf("failed to extract public key from DID %q", didStr)
			}
			return pubKey, nil
		}
		return webResolver.Resolve(ctx, didStr, kid)
	}
}

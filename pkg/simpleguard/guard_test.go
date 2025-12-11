package simpleguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleGuard_SignAndVerify(t *testing.T) {
	// Generate keys
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cfg := Config{
		AgentID:    "test-agent",
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      "test-key-1",
	}

	guard, err := New(cfg)
	require.NoError(t, err)

	t.Run("Valid Token", func(t *testing.T) {
		payload := Claims{Subject: "test-subject"}
		body := []byte(`{"foo":"bar"}`)

		token, err := guard.SignOutbound(payload, body)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		verified, err := guard.VerifyInbound(token, body)
		require.NoError(t, err)
		assert.Equal(t, "test-subject", verified.Subject)
		assert.Equal(t, "test-agent", verified.Issuer)
		assert.NotEmpty(t, verified.BodyHash)
	})

	t.Run("Tampered Body", func(t *testing.T) {
		payload := Claims{Subject: "test-subject"}
		body := []byte(`{"foo":"bar"}`)
		tamperedBody := []byte(`{"foo":"baz"}`)

		token, err := guard.SignOutbound(payload, body)
		require.NoError(t, err)

		_, err = guard.VerifyInbound(token, tamperedBody)
		assert.ErrorIs(t, err, ErrIntegrityFailed)
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Manually create expired token
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, nil)
		require.NoError(t, err)

		claims := Claims{
			Subject:  "test-subject",
			Issuer:   "test-agent",
			IssuedAt: time.Now().Add(-2 * time.Minute).Unix(),
			Expiry:   time.Now().Add(-1 * time.Minute).Unix(),
		}

		b, err := json.Marshal(claims)
		require.NoError(t, err)
		jws, err := signer.Sign(b)
		require.NoError(t, err)
		token, err := jws.CompactSerialize()
		require.NoError(t, err)

		_, err = guard.VerifyInbound(token, nil)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("DevMode Auto-Generation", func(t *testing.T) {
		cfg := Config{DevMode: true}
		guard, err := New(cfg)
		require.NoError(t, err)

		// Should be able to sign and verify with auto-generated keys
		payload := Claims{Subject: "dev-subject"}
		token, err := guard.SignOutbound(payload, nil)
		require.NoError(t, err)

		verified, err := guard.VerifyInbound(token, nil)
		require.NoError(t, err)
		assert.Equal(t, "dev-subject", verified.Subject)
		assert.Equal(t, "dev-agent", verified.Issuer)
	})

	t.Run("Empty Body No Hash", func(t *testing.T) {
		payload := Claims{Subject: "no-body"}
		token, err := guard.SignOutbound(payload, nil)
		require.NoError(t, err)

		verified, err := guard.VerifyInbound(token, nil)
		require.NoError(t, err)
		assert.Equal(t, "no-body", verified.Subject)
		assert.Empty(t, verified.BodyHash)
	})

	t.Run("Body Hash Present But No Body", func(t *testing.T) {
		payload := Claims{Subject: "with-body"}
		body := []byte(`{"data":"test"}`)
		token, err := guard.SignOutbound(payload, body)
		require.NoError(t, err)

		// Verify with empty body should fail
		_, err = guard.VerifyInbound(token, nil)
		assert.ErrorIs(t, err, ErrIntegrityFailed)
	})

	t.Run("Invalid Token Format", func(t *testing.T) {
		_, err := guard.VerifyInbound("not-a-valid-token", nil)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		// Sign with different key
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		otherSigner, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: otherPriv}, nil)
		claims := Claims{Subject: "test", IssuedAt: time.Now().Unix(), Expiry: time.Now().Add(time.Minute).Unix()}
		b, _ := json.Marshal(claims)
		jws, _ := otherSigner.Sign(b)
		token, _ := jws.CompactSerialize()

		_, err := guard.VerifyInbound(token, nil)
		assert.ErrorIs(t, err, ErrSignatureInvalid)
	})

	t.Run("Future Token", func(t *testing.T) {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, nil)
		claims := Claims{
			Subject:  "future",
			IssuedAt: time.Now().Add(10 * time.Minute).Unix(),
			Expiry:   time.Now().Add(15 * time.Minute).Unix(),
		}
		b, _ := json.Marshal(claims)
		jws, _ := signer.Sign(b)
		token, _ := jws.CompactSerialize()

		_, err := guard.VerifyInbound(token, nil)
		assert.ErrorIs(t, err, ErrTokenFuture)
	})

	t.Run("Token Too Old", func(t *testing.T) {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, nil)
		claims := Claims{
			Subject:  "old",
			IssuedAt: time.Now().Add(-5 * time.Minute).Unix(),
			Expiry:   time.Now().Add(5 * time.Minute).Unix(), // Not expired but too old
		}
		b, _ := json.Marshal(claims)
		jws, _ := signer.Sign(b)
		token, _ := jws.CompactSerialize()

		_, err := guard.VerifyInbound(token, nil)
		assert.ErrorIs(t, err, ErrTokenExpired)
	})
}

func TestNew_InvalidKey(t *testing.T) {
	// Test with unsupported key type
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cfg := Config{
		AgentID:    "test",
		PrivateKey: rsaKey,
		KeyID:      "test-key",
	}

	_, err := New(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported private key type")
}

func TestMiddleware(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{
		AgentID:    "test-agent",
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      "test-key",
	}
	guard, _ := New(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := SubjectFromContext(r.Context())
		claims := ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("subject:" + subject + ",issuer:" + claims.Issuer))
	})

	middleware := Middleware(guard)
	server := middleware(handler)

	t.Run("Missing Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Capiscio-Badge", "invalid-token")
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("Valid Token", func(t *testing.T) {
		token, _ := guard.SignOutbound(Claims{Subject: "my-subject"}, nil)
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Capiscio-Badge", token)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "subject:my-subject")
		assert.Contains(t, rec.Body.String(), "issuer:test-agent")
		assert.NotEmpty(t, rec.Header().Get("Server-Timing"))
	})

	t.Run("Valid Token With Body", func(t *testing.T) {
		body := `{"data":"test"}`
		token, _ := guard.SignOutbound(Claims{Subject: "body-subject"}, []byte(body))
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		req.Header.Set("X-Capiscio-Badge", token)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Body Too Large", func(t *testing.T) {
		// Create guard with small body limit
		smallCfg := Config{
			AgentID:     "test",
			PrivateKey:  priv,
			PublicKey:   pub,
			KeyID:       "test",
			MaxBodySize: 10, // 10 bytes max
		}
		smallGuard, _ := New(smallCfg)
		smallMiddleware := Middleware(smallGuard)
		smallServer := smallMiddleware(handler)

		largeBody := strings.Repeat("x", 100)
		token, _ := smallGuard.SignOutbound(Claims{Subject: "large"}, []byte(largeBody))
		req := httptest.NewRequest("POST", "/test", strings.NewReader(largeBody))
		req.Header.Set("X-Capiscio-Badge", token)
		rec := httptest.NewRecorder()
		smallServer.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
}

func TestContextHelpers(t *testing.T) {
	t.Run("SubjectFromContext Empty", func(t *testing.T) {
		ctx := context.Background()
		assert.Empty(t, SubjectFromContext(ctx))
	})

	t.Run("SubjectFromContext With Value", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeySubject, "test-subject")
		assert.Equal(t, "test-subject", SubjectFromContext(ctx))
	})

	t.Run("SubjectFromContext Wrong Type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeySubject, 123)
		assert.Empty(t, SubjectFromContext(ctx))
	})

	t.Run("ClaimsFromContext Empty", func(t *testing.T) {
		ctx := context.Background()
		assert.Nil(t, ClaimsFromContext(ctx))
	})

	t.Run("ClaimsFromContext With Value", func(t *testing.T) {
		claims := &Claims{Subject: "test"}
		ctx := context.WithValue(context.Background(), ContextKeyClaims, claims)
		assert.Equal(t, claims, ClaimsFromContext(ctx))
	})

	t.Run("ClaimsFromContext Wrong Type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyClaims, "not-claims")
		assert.Nil(t, ClaimsFromContext(ctx))
	})
}

func TestMiddleware_BodyReadError(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{
		AgentID:    "test-agent",
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      "test-key",
	}
	guard, _ := New(cfg)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := Middleware(guard)
	server := middleware(handler)

	// Create request with error-producing body
	req := httptest.NewRequest("POST", "/test", &errorReader{})
	token, _ := guard.SignOutbound(Claims{Subject: "test"}, nil)
	req.Header.Set("X-Capiscio-Badge", token)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

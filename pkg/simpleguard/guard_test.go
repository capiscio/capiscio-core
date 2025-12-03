package simpleguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
}

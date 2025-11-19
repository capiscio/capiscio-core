package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockJWKSFetcher is a mock implementation of JWKSFetcher
type MockJWKSFetcher struct {
	mock.Mock
}

func (m *MockJWKSFetcher) Fetch(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {
	args := m.Called(ctx, url)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jose.JSONWebKeySet), args.Error(1)
}

func TestVerifier_VerifyAgentCardSignatures_NoSignatures(t *testing.T) {
	verifier := NewVerifier()
	card := &agentcard.AgentCard{
		Name: "Test Agent",
	}

	result, err := verifier.VerifyAgentCardSignatures(context.Background(), card)
	assert.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 0, result.Summary.Total)
	assert.Contains(t, result.Summary.Errors, "No signatures present in Agent Card")
}

func TestVerifier_VerifyAgentCardSignatures_InvalidHeader(t *testing.T) {
	verifier := NewVerifier()
	card := &agentcard.AgentCard{
		Name: "Test Agent",
		Signatures: []agentcard.Signature{
			{Protected: "invalid-base64", Signature: "sig"},
		},
	}

	result, err := verifier.VerifyAgentCardSignatures(context.Background(), card)
	assert.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.Summary.Total)
	assert.Equal(t, 1, result.Summary.Failed)
	// The error message might vary depending on exactly how the base64 decoding fails or if it falls through to JSON unmarshal
	// "invalid-base64" contains a hyphen which is valid in base64url, so it might decode but fail JSON unmarshal
	// Let's check for either error
	assert.True(t,
		strings.Contains(result.Signatures[0].Error, "invalid protected header encoding") ||
			strings.Contains(result.Signatures[0].Error, "invalid protected header json"),
		"Error should be about encoding or json: %s", result.Signatures[0].Error,
	)
}

func TestVerifier_VerifyAgentCardSignatures_Success(t *testing.T) {
	// 1. Generate Key Pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// 2. Create JWKS
	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "kid1",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	// 3. Mock Fetcher
	mockFetcher := new(MockJWKSFetcher)
	mockFetcher.On("Fetch", mock.Anything, "https://example.com/.well-known/jwks.json").Return(&jwks, nil)

	verifier := NewVerifierWithFetcher(mockFetcher)

	// 4. Create Agent Card
	card := &agentcard.AgentCard{
		Name: "Test Agent",
		URL:  "https://example.com",
	}

	// 5. Sign the card
	// We need to replicate the signing process: Canonicalize -> Sign
	canonicalJSON, err := CreateCanonicalJSON(card)
	assert.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): "kid1",
			jose.HeaderKey("jku"): "https://example.com/.well-known/jwks.json",
		},
	})
	assert.NoError(t, err)

	jws, err := signer.Sign(canonicalJSON)
	assert.NoError(t, err)

	// Extract parts to put into AgentCardSignature
	// JWS Compact Serialization: header.payload.signature
	compact, err := jws.CompactSerialize()
	assert.NoError(t, err)
	parts := strings.Split(compact, ".")
	assert.Equal(t, 3, len(parts))

	card.Signatures = []agentcard.Signature{
		{
			Protected: parts[0],
			Signature: parts[2],
		},
	}

	// 6. Verify
	result, err := verifier.VerifyAgentCardSignatures(context.Background(), card)
	assert.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, 1, result.Summary.Total)
	assert.Equal(t, 1, result.Summary.Valid)
	assert.Equal(t, 0, result.Summary.Failed)
}

func TestVerifier_VerifyAgentCardSignatures_TamperedPayload(t *testing.T) {
	// 1. Generate Key Pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// 2. Create JWKS
	jwk := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     "kid1",
		Algorithm: "RS256",
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	// 3. Mock Fetcher
	mockFetcher := new(MockJWKSFetcher)
	mockFetcher.On("Fetch", mock.Anything, "https://example.com/.well-known/jwks.json").Return(&jwks, nil)

	verifier := NewVerifierWithFetcher(mockFetcher)

	// 4. Create Agent Card and Sign it
	card := &agentcard.AgentCard{
		Name: "Test Agent",
		URL:  "https://example.com",
	}
	canonicalJSON, _ := CreateCanonicalJSON(card)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): "kid1",
			jose.HeaderKey("jku"): "https://example.com/.well-known/jwks.json",
		},
	})
	jws, _ := signer.Sign(canonicalJSON)
	compact, _ := jws.CompactSerialize()
	parts := strings.Split(compact, ".")

	card.Signatures = []agentcard.Signature{
		{
			Protected: parts[0],
			Signature: parts[2],
		},
	}

	// 5. Tamper with the card (change Name)
	card.Name = "Tampered Agent"

	// 6. Verify
	result, err := verifier.VerifyAgentCardSignatures(context.Background(), card)
	assert.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Equal(t, 1, result.Summary.Total)
	assert.Equal(t, 1, result.Summary.Failed)
	assert.Contains(t, result.Signatures[0].Error, "signature verification failed")
}

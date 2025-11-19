package scoring

import (
	"testing"

	"github.com/capiscio/capiscio-core/pkg/crypto"
	"github.com/stretchr/testify/assert"
)

func TestTrustScorer_Score_NoSignatures(t *testing.T) {
	scorer := NewTrustScorer(nil)

	// Nil result
	score, issues := scorer.Score(nil)
	assert.Equal(t, 20.0, score)
	assert.Equal(t, "NO_SIGNATURES", issues[0].Code)

	// Empty signatures
	res := &crypto.SignatureVerificationResult{
		Valid:      false,
		Signatures: []crypto.SignatureResult{},
	}
	score, issues = scorer.Score(res)
	assert.Equal(t, 20.0, score)
	assert.Equal(t, "NO_SIGNATURES", issues[0].Code)
}

func TestTrustScorer_Score_ValidSignatures(t *testing.T) {
	scorer := NewTrustScorer(nil)

	res := &crypto.SignatureVerificationResult{
		Valid: true,
		Signatures: []crypto.SignatureResult{
			{Valid: true, Algorithm: "RS256", JWKSUri: "https://example.com/jwks"},
		},
	}

	score, issues := scorer.Score(res)
	assert.Equal(t, 80.0, score)
	assert.Empty(t, issues)
}

func TestTrustScorer_Score_InvalidSignatures(t *testing.T) {
	scorer := NewTrustScorer(nil)

	res := &crypto.SignatureVerificationResult{
		Valid: false,
		Signatures: []crypto.SignatureResult{
			{Valid: false, Error: "Bad signature"},
		},
		Summary: crypto.VerificationSummary{
			Errors: []string{"Bad signature"},
		},
	}

	score, issues := scorer.Score(res)
	assert.Equal(t, 0.0, score)
	assert.Equal(t, "INVALID_SIGNATURES", issues[0].Code)
	assert.Equal(t, "SIGNATURE_ERROR", issues[1].Code)
}

func TestTrustScorer_Score_TrustedIssuer(t *testing.T) {
	trusted := []string{"https://trusted.com/jwks"}
	scorer := NewTrustScorer(trusted)

	// 1. Trusted Issuer
	res := &crypto.SignatureVerificationResult{
		Valid: true,
		Signatures: []crypto.SignatureResult{
			{Valid: true, Algorithm: "RS256", JWKSUri: "https://trusted.com/jwks"},
		},
	}
	score, issues := scorer.Score(res)
	assert.Equal(t, 100.0, score)
	assert.Empty(t, issues)

	// 2. Untrusted Issuer
	res = &crypto.SignatureVerificationResult{
		Valid: true,
		Signatures: []crypto.SignatureResult{
			{Valid: true, Algorithm: "RS256", JWKSUri: "https://untrusted.com/jwks"},
		},
	}
	score, issues = scorer.Score(res)
	assert.Equal(t, 60.0, score)
	assert.Len(t, issues, 1)
	assert.Equal(t, "UNTRUSTED_ISSUER", issues[0].Code)
}

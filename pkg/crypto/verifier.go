package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/go-jose/go-jose/v4"
)

// SignatureVerificationResult contains the result of verifying all signatures.
type SignatureVerificationResult struct {
	Valid      bool
	Signatures []SignatureResult
	Summary    VerificationSummary
}

type SignatureResult struct {
	Index     int
	Valid     bool
	Algorithm string
	KeyID     string
	Issuer    string
	JWKSUri   string
	Error     string
}

type VerificationSummary struct {
	Total  int
	Valid  int
	Failed int
	Errors []string
}

// Verifier handles Agent Card signature verification.
type Verifier struct {
	jwksFetcher JWKSFetcher
}

// NewVerifier creates a new Verifier with the default JWKS fetcher.
func NewVerifier() *Verifier {
	return &Verifier{
		jwksFetcher: NewDefaultJWKSFetcher(),
	}
}

// NewVerifierWithFetcher creates a new Verifier with a custom JWKS fetcher.
func NewVerifierWithFetcher(fetcher JWKSFetcher) *Verifier {
	return &Verifier{
		jwksFetcher: fetcher,
	}
}

// VerifyAgentCardSignatures verifies all signatures in an Agent Card.
func (v *Verifier) VerifyAgentCardSignatures(ctx context.Context, card *agentcard.AgentCard) (*SignatureVerificationResult, error) {
	if len(card.Signatures) == 0 {
		return &SignatureVerificationResult{
			Valid: false,
			Summary: VerificationSummary{
				Errors: []string{"No signatures present in Agent Card"},
			},
		}, nil
	}

	// Create canonical payload once
	payload, err := CreateCanonicalJSON(card)
	if err != nil {
		return nil, fmt.Errorf("failed to create canonical payload: %w", err)
	}

	var results []SignatureResult
	var errorMsgs []string
	validCount := 0

	for i, sig := range card.Signatures {
		res := v.verifySingleSignature(ctx, payload, sig, i)
		results = append(results, res)
		if res.Valid {
			validCount++
		} else {
			errorMsgs = append(errorMsgs, fmt.Sprintf("Signature %d: %s", i+1, res.Error))
		}
	}

	return &SignatureVerificationResult{
		Valid:      validCount > 0 && validCount == len(card.Signatures),
		Signatures: results,
		Summary: VerificationSummary{
			Total:  len(card.Signatures),
			Valid:  validCount,
			Failed: len(card.Signatures) - validCount,
			Errors: errorMsgs,
		},
	}, nil
}

func (v *Verifier) verifySingleSignature(ctx context.Context, payload []byte, sig agentcard.AgentCardSignature, index int) SignatureResult {
	res := SignatureResult{Index: index}

	// 1. Parse Protected Header
	headerBytes, err := base64.RawURLEncoding.DecodeString(sig.Protected)
	if err != nil {
		res.Error = fmt.Sprintf("invalid protected header encoding: %v", err)
		return res
	}

	var header struct {
		Alg     string `json:"alg"`
		Kid     string `json:"kid"`
		Jku     string `json:"jku"`
		JwksUri string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		res.Error = fmt.Sprintf("invalid protected header json: %v", err)
		return res
	}

	res.Algorithm = header.Alg
	res.KeyID = header.Kid

	// 2. Validate Header
	if header.Alg == "none" || header.Alg == "" {
		res.Error = "algorithm 'none' or empty is not allowed"
		return res
	}

	jwksURL := header.Jku
	if jwksURL == "" {
		jwksURL = header.JwksUri
	}
	if jwksURL == "" {
		res.Error = "missing jku or jwks_uri in header"
		return res
	}
	res.JWKSUri = jwksURL

	u, err := url.Parse(jwksURL)
	if err != nil || u.Scheme != "https" {
		res.Error = "jwks_uri must be a valid https url"
		return res
	}

	// 3. Reconstruct JWS (Detached)
	// JWS Compact Serialization: BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload) || '.' || BASE64URL(JWS Signature)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)
	compactJWS := fmt.Sprintf("%s.%s.%s", sig.Protected, payloadEncoded, sig.Signature)

	jwsObj, err := jose.ParseSigned(compactJWS, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(header.Alg)})
	if err != nil {
		res.Error = fmt.Sprintf("failed to parse JWS: %v", err)
		return res
	}

	// 4. Fetch JWKS
	jwks, err := v.jwksFetcher.Fetch(ctx, jwksURL)
	if err != nil {
		res.Error = fmt.Sprintf("failed to fetch JWKS: %v", err)
		return res
	}

	// 5. Verify
	keys := jwks.Keys
	if len(keys) == 0 {
		res.Error = "empty JWKS"
		return res
	}

	verified := false
	for _, key := range keys {
		if header.Kid != "" && key.KeyID != header.Kid {
			continue
		}
		// Verify returns the payload if successful
		_, err := jwsObj.Verify(key)
		if err == nil {
			verified = true
			break
		}
	}

	if !verified {
		res.Error = "signature verification failed"
		return res
	}

	res.Valid = true
	return res
}

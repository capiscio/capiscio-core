package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
	"github.com/go-jose/go-jose/v4"
)

// SignatureVerificationResult contains the result of verifying all signatures.
type SignatureVerificationResult struct {
	Valid      bool
	Signatures []SignatureResult
	Summary    VerificationSummary
}

// SignatureResult holds the details of a single signature verification.
type SignatureResult struct {
	Index     int
	Valid     bool
	Algorithm string
	KeyID     string
	Issuer    string
	JWKSUri   string
	Error     string
}

// VerificationSummary summarizes the results of all signature verifications.
type VerificationSummary struct {
	Total  int
	Valid  int
	Failed int
	Errors []string
}

type protectedHeader struct {
	Alg     string `json:"alg"`
	Kid     string `json:"kid"`
	Jku     string `json:"jku"`
	JwksURI string `json:"jwks_uri"`
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

func (v *Verifier) verifySingleSignature(ctx context.Context, payload []byte, sig agentcard.Signature, index int) SignatureResult {
	res := SignatureResult{Index: index}

	// 1. Parse Protected Header
	header, err := v.parseHeader(sig)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	res.Algorithm = header.Alg
	res.KeyID = header.Kid

	// 2. Validate Header
	jwksURL, err := v.validateHeader(header)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.JWKSUri = jwksURL

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
	if err := v.verifyJWS(jwsObj, jwks, header.Kid); err != nil {
		res.Error = err.Error()
		return res
	}

	res.Valid = true
	return res
}

func (v *Verifier) parseHeader(sig agentcard.Signature) (protectedHeader, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(sig.Protected)
	if err != nil {
		return protectedHeader{}, fmt.Errorf("invalid protected header encoding: %v", err)
	}

	var header protectedHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return protectedHeader{}, fmt.Errorf("invalid protected header json: %v", err)
	}
	return header, nil
}

func (v *Verifier) validateHeader(header protectedHeader) (string, error) {
	if header.Alg == "none" || header.Alg == "" {
		return "", fmt.Errorf("algorithm 'none' or empty is not allowed")
	}

	jwksURL := header.Jku
	if jwksURL == "" {
		jwksURL = header.JwksURI
	}
	if jwksURL == "" {
		return "", fmt.Errorf("missing jku or jwks_uri in header")
	}

	u, err := url.Parse(jwksURL)
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("jwks_uri must be a valid https url")
	}
	return jwksURL, nil
}

func (v *Verifier) verifyJWS(jwsObj *jose.JSONWebSignature, jwks *jose.JSONWebKeySet, kid string) error {
	keys := jwks.Keys
	if len(keys) == 0 {
		return fmt.Errorf("empty JWKS")
	}

	for _, key := range keys {
		if kid != "" && key.KeyID != kid {
			continue
		}
		// Verify returns the payload if successful
		_, err := jwsObj.Verify(key)
		if err == nil {
			return nil
		}
	}

	return fmt.Errorf("signature verification failed")
}

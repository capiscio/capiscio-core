// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package badge

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/trust"
	"github.com/go-jose/go-jose/v4"
)

// =============================================================================
// LOCAL VERIFIER — RFC-001 §2.3 Compliant
// =============================================================================

// LocalVerifier validates TrustBadges using only locally cached trust material.
// It MUST NOT make any synchronous network calls during verification.
//
// Per RFC-001 §2.3 (Verification Locality Principle):
//   - Verifiers MUST be able to validate any CapiscIO trust artifact using only
//     locally cached cryptographic material and a local revocation cache.
//   - Implementations MUST NOT embed synchronous registry calls in the
//     verification critical path.
type LocalVerifier struct {
	material *trust.MaterialManager
	options  LocalVerifyOptions
}

// LocalVerifyOptions configures local verification behavior.
type LocalVerifyOptions struct {
	// TrustedIssuers is a list of allowed badge issuers.
	// For registry-issued badges (levels 1-4): HTTPS origin URLs per RFC-002 §4.3.1
	// For Level 0 self-signed badges: did:key identifiers.
	// If empty, all issuers with cached keys are accepted.
	TrustedIssuers []string

	// AcceptSelfSigned allows Level 0 self-signed badges (did:key issuer).
	// WARNING: Production verifiers SHOULD NOT accept self-signed badges.
	// Default: false (reject self-signed badges)
	AcceptSelfSigned bool

	// Audience is the verifier's identity for audience validation.
	Audience string

	// Now overrides the current time (for testing).
	Now func() time.Time
}

// LocalVerifyResult contains the result of local verification.
type LocalVerifyResult struct {
	// Claims contains the verified badge claims.
	Claims *Claims

	// Freshness indicates the freshness state of trust material used.
	Freshness trust.FreshnessState

	// Warnings contains non-fatal issues encountered.
	Warnings []string
}

// NewLocalVerifier creates a verifier that operates locally against cached material.
// This is the RFC-001 §2.3 compliant verification path.
//
// The MaterialManager must be bootstrapped before use. If no trust material is
// available, verification will fail with ErrNoTrustMaterial.
func NewLocalVerifier(material *trust.MaterialManager, opts LocalVerifyOptions) *LocalVerifier {
	return &LocalVerifier{
		material: material,
		options:  opts,
	}
}

// Verify validates a badge using locally cached trust material.
// This method NEVER makes network calls — it operates purely against cached data.
//
// Returns error if:
// - Trust material is not bootstrapped
// - Issuer key is not cached
// - Signature verification fails
// - Badge is expired
// - Badge is revoked (if revocation cache is available)
func (v *LocalVerifier) Verify(ctx context.Context, token string) (*LocalVerifyResult, error) {
	// Check material manager is present and bootstrapped
	if v.material == nil || !v.material.IsBootstrapped() {
		return nil, trust.ErrNoTrustMaterial
	}

	// Parse JWS and extract claims
	jwsObj, claims, err := v.parseJWSAndClaims(token)
	if err != nil {
		return nil, err
	}

	result := &LocalVerifyResult{
		Freshness: trust.FreshnessStateFresh,
	}

	// Determine issuer type and validate
	issuerDID, isSelfSigned, err := v.parseAndValidateIssuer(claims)
	if err != nil {
		return nil, err
	}

	// Get public key from local material
	pubKey, freshness, err := v.getPublicKeyLocal(jwsObj, claims, issuerDID, isSelfSigned)
	if err != nil {
		return nil, err
	}
	result.Freshness = freshness

	// Verify signature
	verifiedClaims, err := v.verifySignature(jwsObj, pubKey)
	if err != nil {
		return nil, err
	}
	result.Claims = verifiedClaims

	// Validate standard claims
	if err := v.validateStandardClaims(verifiedClaims); err != nil {
		return nil, err
	}

	// Check revocation and handle errors
	if err := v.handleRevocationCheck(verifiedClaims.JTI, result); err != nil {
		return nil, err
	}

	return result, nil
}

// parseAndValidateIssuer parses the issuer claim and validates self-signed acceptance.
func (v *LocalVerifier) parseAndValidateIssuer(claims *Claims) (*did.DID, bool, error) {
	var issuerDID *did.DID
	var isSelfSigned bool

	parsedDID, didErr := did.Parse(claims.Issuer)
	if didErr == nil {
		issuerDID = parsedDID
		isSelfSigned = issuerDID.IsKeyDID()
	} else if isHTTPSOrigin(claims.Issuer) {
		isSelfSigned = false
	} else {
		return nil, false, WrapError(ErrCodeClaimsInvalid, "invalid issuer: must be a DID or HTTPS origin URL", didErr)
	}

	// Check self-signed acceptance
	if isSelfSigned && !v.options.AcceptSelfSigned {
		return nil, false, WrapError(ErrCodeIssuerUntrusted, "self-signed badges not accepted", nil)
	}

	// Check trusted issuers
	if err := v.checkTrustedIssuer(claims.Issuer, isSelfSigned); err != nil {
		return nil, false, err
	}

	return issuerDID, isSelfSigned, nil
}

// handleRevocationCheck checks revocation status and updates result.
func (v *LocalVerifier) handleRevocationCheck(jti string, result *LocalVerifyResult) error {
	revoked, revFreshness, err := v.checkRevocationLocal(jti)
	if err != nil {
		// Check if this is a stale data error from FailClosed policy
		if _, isStaleErr := err.(*trust.StaleRevocationDataError); isStaleErr {
			return WrapError(ErrCodeRevocationCheckFailed, "revocation data is stale (FailClosed policy)", err)
		}
		// For other errors, add warning but don't block
		result.Warnings = append(result.Warnings, fmt.Sprintf("revocation check failed: %v", err))
	} else if revoked {
		return WrapError(ErrCodeRevoked, "badge has been revoked", nil)
	}

	// Use worst freshness state
	if revFreshness > result.Freshness {
		result.Freshness = revFreshness
	}

	// Add freshness warning if degraded
	if result.Freshness == trust.FreshnessStateDegraded {
		result.Warnings = append(result.Warnings, "verification used stale trust material")
	}

	return nil
}

// VerifyWithMaterial validates a badge using explicitly provided trust material.
// This is useful for testing or environments with custom trust bundles.
func (v *LocalVerifier) VerifyWithMaterial(token string, material *trust.TrustMaterial) (*LocalVerifyResult, error) {
	// Create a temporary MaterialManager from the bundle
	mgr, err := trust.BootstrapFromBundle(material, trust.DefaultFreshnessPolicy())
	if err != nil {
		return nil, fmt.Errorf("failed to create material manager: %w", err)
	}
	defer mgr.Close()

	// Create a temporary verifier with the explicit material
	tempVerifier := &LocalVerifier{
		material: mgr,
		options:  v.options,
	}

	return tempVerifier.Verify(context.Background(), token)
}

// parseJWSAndClaims parses JWS token and extracts unverified claims.
func (v *LocalVerifier) parseJWSAndClaims(token string) (*jose.JSONWebSignature, *Claims, error) {
	jwsObj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return nil, nil, WrapError(ErrCodeMalformed, "failed to parse JWS", err)
	}

	unsafePayload := jwsObj.UnsafePayloadWithoutVerification()
	var claims Claims
	if err := json.Unmarshal(unsafePayload, &claims); err != nil {
		return nil, nil, WrapError(ErrCodeMalformed, "failed to unmarshal claims", err)
	}

	return jwsObj, &claims, nil
}

// getPublicKeyLocal retrieves the public key from local trust material.
func (v *LocalVerifier) getPublicKeyLocal(jwsObj *jose.JSONWebSignature, claims *Claims, issuerDID *did.DID, isSelfSigned bool) (crypto.PublicKey, trust.FreshnessState, error) {
	if isSelfSigned {
		// For self-signed, extract key from issuer DID
		if issuerDID == nil {
			return nil, trust.FreshnessStateExpired, WrapError(ErrCodeIssuerUntrusted, "missing issuer DID for self-signed badge", nil)
		}
		pubKey := issuerDID.GetPublicKey()
		if pubKey == nil {
			return nil, trust.FreshnessStateExpired, WrapError(ErrCodeIssuerUntrusted, "failed to extract public key from did:key", nil)
		}
		return pubKey, trust.FreshnessStateFresh, nil
	}

	// Get kid from JWS header (issuer signing key), not from CNF (subject's PoP key)
	kid := ""
	if len(jwsObj.Signatures) > 0 {
		kid = jwsObj.Signatures[0].Header.KeyID
	}

	// Get from local material - try with kid first, fall back to empty kid (returns first key)
	pubKey, freshness, err := v.material.GetPublicKey(claims.Issuer, kid)
	if err != nil && kid != "" {
		// Kid specified but not found - try without kid for backwards compatibility
		// (some issuers may not include kid in JWS header, or cache may not have kid mapping)
		pubKey, freshness, err = v.material.GetPublicKey(claims.Issuer, "")
	}
	if err != nil {
		return nil, freshness, WrapError(ErrCodeIssuerUntrusted,
			fmt.Sprintf("issuer key not found in local cache: %s", claims.Issuer), err)
	}

	return pubKey.(crypto.PublicKey), freshness, nil
}

// verifySignature verifies the JWS signature.
func (v *LocalVerifier) verifySignature(jwsObj *jose.JSONWebSignature, pubKey crypto.PublicKey) (*Claims, error) {
	payload, err := jwsObj.Verify(pubKey)
	if err != nil {
		return nil, WrapError(ErrCodeSignatureInvalid, "signature verification failed", err)
	}

	var verifiedClaims Claims
	if err := json.Unmarshal(payload, &verifiedClaims); err != nil {
		return nil, WrapError(ErrCodeMalformed, "failed to unmarshal verified claims", err)
	}
	return &verifiedClaims, nil
}

// validateStandardClaims validates exp, nbf, iat, and other standard claims.
func (v *LocalVerifier) validateStandardClaims(claims *Claims) error {
	now := time.Now()
	if v.options.Now != nil {
		now = v.options.Now()
	}

	// Check expiration (exp is Unix timestamp int64)
	if claims.Expiry > 0 && time.Unix(claims.Expiry, 0).Before(now) {
		return WrapError(ErrCodeExpired, "badge has expired", nil)
	}

	// Check not-before (nbf is Unix timestamp int64)
	if claims.NotBefore > 0 && time.Unix(claims.NotBefore, 0).After(now) {
		return WrapError(ErrCodeNotYetValid, "badge is not yet valid", nil)
	}

	// Check issued-at (iat) is not in the future
	if claims.IssuedAt > 0 && time.Unix(claims.IssuedAt, 0).After(now) {
		return WrapError(ErrCodeNotYetValid, "badge issued-at time is in the future", nil)
	}

	// Check audience if configured
	if v.options.Audience != "" && len(claims.Audience) > 0 {
		found := false
		for _, aud := range claims.Audience {
			if aud == v.options.Audience {
				found = true
				break
			}
		}
		if !found {
			return WrapError(ErrCodeAudienceMismatch, "verifier not in badge audience", nil)
		}
	}

	return nil
}

// checkTrustedIssuer validates the issuer is in the trusted list.
func (v *LocalVerifier) checkTrustedIssuer(issuer string, isSelfSigned bool) error {
	if len(v.options.TrustedIssuers) == 0 {
		// No trusted list configured — allow any issuer with cached keys
		return nil
	}

	for _, trusted := range v.options.TrustedIssuers {
		if issuer == trusted {
			return nil
		}
	}

	return WrapError(ErrCodeIssuerUntrusted, fmt.Sprintf("issuer %s not in trusted list", issuer), nil)
}

// checkRevocationLocal checks revocation against local cache.
func (v *LocalVerifier) checkRevocationLocal(jti string) (bool, trust.FreshnessState, error) {
	return v.material.IsRevoked(jti)
}

// =============================================================================
// BACKWARD COMPATIBILITY
// =============================================================================

// NewVerifierWithTrustMaterial creates a local verifier from a MaterialManager.
// This is an alias for NewLocalVerifier for API consistency.
//
// Deprecated: Use NewLocalVerifier directly for new code.
func NewVerifierWithTrustMaterial(material *trust.MaterialManager) *LocalVerifier {
	return NewLocalVerifier(material, LocalVerifyOptions{})
}

// VerifyOptions adapter for LocalVerifyOptions conversion
func (o VerifyOptions) ToLocalOptions() LocalVerifyOptions {
	return LocalVerifyOptions{
		TrustedIssuers:   o.TrustedIssuers,
		AcceptSelfSigned: o.AcceptSelfSigned,
		Audience:         o.Audience,
		Now:              o.Now,
	}
}

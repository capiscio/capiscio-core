package badge

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
	"github.com/go-jose/go-jose/v4"
)

// VerifyMode determines how verification is performed.
type VerifyMode int

const (
	// VerifyModeOnline performs real-time checks against the registry.
	// This includes revocation checks and agent status checks.
	VerifyModeOnline VerifyMode = iota

	// VerifyModeOffline uses only local trust store and revocation cache.
	// Does not make network requests.
	VerifyModeOffline

	// VerifyModeHybrid uses online checks when available, falls back to cache.
	VerifyModeHybrid
)

// VerifyOptions configures badge verification behavior.
type VerifyOptions struct {
	// Mode determines online/offline verification behavior.
	Mode VerifyMode

	// TrustedIssuers is a list of allowed issuer DIDs (did:web or did:key).
	// If empty, all issuers are accepted (not recommended for production).
	// For Level 0 self-signed badges, the did:key issuer must be in this list
	// or AcceptSelfSigned must be true.
	TrustedIssuers []string

	// AcceptSelfSigned allows Level 0 self-signed badges (did:key issuer).
	// WARNING: Production verifiers SHOULD NOT accept self-signed badges
	// unless explicitly required for specific use cases.
	// Default: false (reject self-signed badges)
	AcceptSelfSigned bool

	// Audience is the verifier's identity for audience validation.
	// If set and badge has aud claim, verifier must be in audience.
	Audience string

	// SkipRevocationCheck disables revocation checking (for testing only).
	SkipRevocationCheck bool

	// SkipAgentStatusCheck disables agent status checking (for testing only).
	SkipAgentStatusCheck bool

	// RevocationCache provides cached revocations for offline mode.
	RevocationCache RevocationCache

	// Now overrides the current time (for testing).
	Now func() time.Time
}

// RevocationCache provides access to cached revocation data.
type RevocationCache interface {
	// IsRevoked checks if a badge jti is in the revocation cache.
	IsRevoked(jti string) bool

	// IsStale returns true if the cache is older than the threshold.
	IsStale(threshold time.Duration) bool
}

// VerifyResult contains the result of badge verification.
type VerifyResult struct {
	// Claims contains the verified badge claims.
	Claims *Claims

	// Mode indicates which verification mode was used.
	Mode VerifyMode

	// Warnings contains non-fatal issues encountered.
	Warnings []string
}

// Verifier validates TrustBadges per RFC-002.
type Verifier struct {
	registry registry.Registry
}

// NewVerifier creates a new Badge Verifier.
func NewVerifier(reg registry.Registry) *Verifier {
	return &Verifier{
		registry: reg,
	}
}

// Verify checks the validity of a TrustBadge JWS token using default options.
// For more control, use VerifyWithOptions.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	result, err := v.VerifyWithOptions(ctx, token, VerifyOptions{
		Mode: VerifyModeOnline,
	})
	if err != nil {
		return nil, err
	}
	return result.Claims, nil
}

// parseJWSAndClaims parses JWS token and extracts unverified claims.
func (v *Verifier) parseJWSAndClaims(token string) (*jose.JSONWebSignature, *Claims, error) {
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

// getPublicKey retrieves the public key for verification based on issuer type.
func (v *Verifier) getPublicKey(ctx context.Context, issuerDID *did.DID, isSelfSigned bool, issuer string) (crypto.PublicKey, error) {
	if isSelfSigned {
		return issuerDID.GetPublicKey(), nil
	}
	// Fetch CA public key from registry
	pubKey, err := v.registry.GetPublicKey(ctx, issuer)
	if err != nil {
		return nil, WrapError(ErrCodeIssuerUntrusted, fmt.Sprintf("failed to fetch public key for issuer %s", issuer), err)
	}
	return pubKey, nil
}

// verifySignature verifies the JWS signature and returns verified claims.
func (v *Verifier) verifySignature(jwsObj *jose.JSONWebSignature, pubKey crypto.PublicKey) (*Claims, error) {
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

// handlePostVerificationChecks performs revocation and agent status checks.
func (v *Verifier) handlePostVerificationChecks(ctx context.Context, claims *Claims, opts VerifyOptions, isSelfSigned bool, result *VerifyResult) error {
	// Check revocation (skip for self-signed)
	if isSelfSigned {
		result.Warnings = append(result.Warnings, "revocation check skipped (self-signed badge)")
	} else if !opts.SkipRevocationCheck {
		if err := v.checkRevocation(ctx, claims, opts); err != nil {
			return err
		}
	}

	// Check agent status (skip for self-signed)
	if isSelfSigned {
		result.Warnings = append(result.Warnings, "agent status check skipped (self-signed badge)")
	} else if !opts.SkipAgentStatusCheck {
		if err := v.checkAgentStatus(ctx, claims, opts, result); err != nil {
			return err
		}
	}

	return nil
}

// VerifyWithOptions performs badge verification with the specified options.
// Implements RFC-002 §8.1 verification flow.
//
// For Level 0 self-signed badges (did:key issuer):
//   - Public key is extracted from the did:key identifier
//   - Revocation check is skipped (self-signed badges not in registry)
//   - Agent status check is skipped (no registry)
//   - iss must equal sub (self-assertion only)
func (v *Verifier) VerifyWithOptions(ctx context.Context, token string, opts VerifyOptions) (*VerifyResult, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	result := &VerifyResult{Mode: opts.Mode}

	// Step 1-2: Parse JWS and extract claims
	jwsObj, claims, err := v.parseJWSAndClaims(token)
	if err != nil {
		return nil, err
	}

	// Step 3: Validate structure
	if err := v.validateStructure(jwsObj, claims); err != nil {
		return nil, err
	}

	// Step 4: Determine if self-signed (did:key issuer)
	issuerDID, err := did.Parse(claims.Issuer)
	if err != nil {
		return nil, WrapError(ErrCodeClaimsInvalid, "invalid issuer DID", err)
	}
	isSelfSigned := issuerDID.IsKeyDID()

	// Step 4a: For self-signed badges, validate Level 0 constraints
	if isSelfSigned {
		if err := v.validateSelfSigned(claims, opts); err != nil {
			return nil, err
		}
	}

	// Step 4b: Get public key (from did:key or registry)
	pubKey, err := v.getPublicKey(ctx, issuerDID, isSelfSigned, claims.Issuer)
	if err != nil {
		return nil, err
	}

	// Step 5: Verify Signature
	verifiedClaims, err := v.verifySignature(jwsObj, pubKey)
	if err != nil {
		return nil, err
	}

	// Step 6: Validate claims
	if err := v.validateClaims(verifiedClaims, opts, now(), isSelfSigned); err != nil {
		return nil, err
	}

	// Step 7-8: Check revocation and agent status
	if err := v.handlePostVerificationChecks(ctx, verifiedClaims, opts, isSelfSigned, result); err != nil {
		return nil, err
	}

	result.Claims = verifiedClaims
	return result, nil
}

// validateSelfSigned validates Level 0 self-signed badge constraints per RFC-002 v1.1.
func (v *Verifier) validateSelfSigned(claims *Claims, opts VerifyOptions) error {
	// Check if self-signed badges are accepted
	if !opts.AcceptSelfSigned {
		// Check if issuer is in trusted issuers list (explicitly trusted did:key)
		trusted := false
		for _, iss := range opts.TrustedIssuers {
			if claims.Issuer == iss {
				trusted = true
				break
			}
		}
		if !trusted {
			return NewError(ErrCodeIssuerUntrusted,
				"self-signed badges (did:key issuer) are not accepted; set AcceptSelfSigned=true or add issuer to TrustedIssuers")
		}
	}

	// RFC-002 v1.1 §4.3.1: For Level 0, iss MUST equal sub
	if claims.Issuer != claims.Subject {
		return NewError(ErrCodeClaimsInvalid,
			fmt.Sprintf("self-signed badge requires iss == sub, got iss=%s, sub=%s", claims.Issuer, claims.Subject))
	}

	// RFC-002 v1.1 §4.3.3: Level MUST be "0" for self-signed
	level := claims.TrustLevel()
	if level != "0" {
		return NewError(ErrCodeClaimsInvalid,
			fmt.Sprintf("self-signed badge (did:key issuer) must have level \"0\", got \"%s\"", level))
	}

	return nil
}

// validateStructure checks header and payload structure per RFC-002 §8.1 step 3.
func (v *Verifier) validateStructure(jwsObj *jose.JSONWebSignature, claims *Claims) error {
	// Check that we have at least one signature
	if len(jwsObj.Signatures) == 0 {
		return NewError(ErrCodeMalformed, "no signatures present")
	}

	// Check algorithm (already enforced by ParseSigned, but be explicit)
	sig := jwsObj.Signatures[0]
	if sig.Header.Algorithm != string(jose.EdDSA) && sig.Header.Algorithm != string(jose.ES256) {
		return NewError(ErrCodeMalformed, fmt.Sprintf("unsupported algorithm: %s", sig.Header.Algorithm))
	}

	// Check required claims
	if claims.JTI == "" {
		return NewError(ErrCodeClaimsInvalid, "missing jti claim")
	}
	if claims.Issuer == "" {
		return NewError(ErrCodeClaimsInvalid, "missing iss claim")
	}
	if claims.Subject == "" {
		return NewError(ErrCodeClaimsInvalid, "missing sub claim")
	}
	if claims.IssuedAt == 0 {
		return NewError(ErrCodeClaimsInvalid, "missing iat claim")
	}
	if claims.Expiry == 0 {
		return NewError(ErrCodeClaimsInvalid, "missing exp claim")
	}

	// Validate subject is a valid DID (did:web or did:key)
	subjectDID, err := did.Parse(claims.Subject)
	if err != nil {
		return WrapError(ErrCodeClaimsInvalid, "invalid subject DID", err)
	}

	// For did:key subjects (Level 0), subject must be same as issuer (validated elsewhere)
	// For did:web subjects (Level 1-4), subject identifies the agent
	_ = subjectDID // Used for validation

	// Check VC structure
	hasVC := false
	hasAgentIdentity := false
	for _, t := range claims.VC.Type {
		if t == "VerifiableCredential" {
			hasVC = true
		}
		if t == "AgentIdentity" {
			hasAgentIdentity = true
		}
	}
	if !hasVC || !hasAgentIdentity {
		return NewError(ErrCodeClaimsInvalid, "vc.type must include VerifiableCredential and AgentIdentity")
	}

	return nil
}

// validateClaims performs claim validation per RFC-002 §8.1 step 6.
func (v *Verifier) validateClaims(claims *Claims, opts VerifyOptions, now time.Time, isSelfSigned bool) error {
	nowUnix := now.Unix()

	// Step 6a: exp > current_time (not expired)
	if claims.Expiry <= nowUnix {
		return NewError(ErrCodeExpired, fmt.Sprintf("badge expired at %s", time.Unix(claims.Expiry, 0).Format(time.RFC3339)))
	}

	// Step 6b: iat <= current_time (not issued in future)
	if claims.IssuedAt > nowUnix {
		return NewError(ErrCodeNotYetValid, fmt.Sprintf("badge not valid until %s", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339)))
	}

	// Step 6c: Issuer in trusted issuer list (unless self-signed with AcceptSelfSigned)
	if len(opts.TrustedIssuers) > 0 && !isSelfSigned {
		trusted := false
		for _, iss := range opts.TrustedIssuers {
			if claims.Issuer == iss {
				trusted = true
				break
			}
		}
		if !trusted {
			return NewError(ErrCodeIssuerUntrusted, fmt.Sprintf("issuer %s not in trusted list", claims.Issuer))
		}
	}
	// Note: self-signed issuer trust is checked in validateSelfSigned()

	// Step 6d: Audience validation
	if opts.Audience != "" && len(claims.Audience) > 0 {
		inAudience := false
		for _, aud := range claims.Audience {
			if aud == opts.Audience {
				inAudience = true
				break
			}
		}
		if !inAudience {
			return NewError(ErrCodeAudienceMismatch, fmt.Sprintf("verifier %s not in badge audience", opts.Audience))
		}
	}

	// Step 6e: Validate trust level range (0-4)
	level := claims.TrustLevel()
	validLevels := map[string]bool{"0": true, "1": true, "2": true, "3": true, "4": true}
	if !validLevels[level] {
		return NewError(ErrCodeClaimsInvalid, fmt.Sprintf("invalid trust level: %s (must be 0-4)", level))
	}

	return nil
}

// checkRevocation performs revocation check per RFC-002 §8.1 step 7.
func (v *Verifier) checkRevocation(ctx context.Context, claims *Claims, opts VerifyOptions) error {
	switch opts.Mode {
	case VerifyModeOnline:
		// Online: Check revocation via registry API
		status, err := v.registry.GetBadgeStatus(ctx, claims.Issuer, claims.JTI)
		if err != nil {
			// If we can't check revocation online, that's an error in online mode
			return WrapError(ErrCodeRevoked, "failed to check revocation status", err)
		}
		if status.Revoked {
			return NewError(ErrCodeRevoked, fmt.Sprintf("badge %s has been revoked", claims.JTI))
		}

	case VerifyModeOffline:
		// Offline: Check local revocation cache
		if opts.RevocationCache != nil && opts.RevocationCache.IsRevoked(claims.JTI) {
			return NewError(ErrCodeRevoked, fmt.Sprintf("badge %s is in revocation cache", claims.JTI))
		}

	case VerifyModeHybrid:
		// Hybrid: Try online first, fall back to cache
		status, err := v.registry.GetBadgeStatus(ctx, claims.Issuer, claims.JTI)
		if err == nil {
			if status.Revoked {
				return NewError(ErrCodeRevoked, fmt.Sprintf("badge %s has been revoked", claims.JTI))
			}
		} else if opts.RevocationCache != nil {
			// Fall back to cache
			if opts.RevocationCache.IsRevoked(claims.JTI) {
				return NewError(ErrCodeRevoked, fmt.Sprintf("badge %s is in revocation cache", claims.JTI))
			}
		}
	}

	return nil
}

// checkAgentStatus performs agent status check per RFC-002 §8.1 step 8.
func (v *Verifier) checkAgentStatus(ctx context.Context, claims *Claims, opts VerifyOptions, result *VerifyResult) error {
	if opts.Mode == VerifyModeOffline {
		// In offline mode, we can't check agent status
		result.Warnings = append(result.Warnings, "agent status not checked (offline mode)")
		return nil
	}

	// Extract agent ID from subject DID
	agentID := claims.AgentID()
	if agentID == "" {
		// Can't extract agent ID, skip check but warn
		result.Warnings = append(result.Warnings, "could not extract agent ID from subject")
		return nil
	}

	status, err := v.registry.GetAgentStatus(ctx, claims.Issuer, agentID)
	if err != nil {
		if opts.Mode == VerifyModeHybrid {
			// In hybrid mode, warn but don't fail
			result.Warnings = append(result.Warnings, fmt.Sprintf("agent status check failed: %v", err))
			return nil
		}
		return WrapError(ErrCodeAgentDisabled, "failed to check agent status", err)
	}

	if !status.IsActive() {
		return NewError(ErrCodeAgentDisabled, fmt.Sprintf("agent %s is %s", agentID, status.Status))
	}

	return nil
}

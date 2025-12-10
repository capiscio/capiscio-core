package badge

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/capiscio/capiscio-core/pkg/did"
	"github.com/capiscio/capiscio-core/pkg/registry"
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

	// TrustedIssuers is a list of allowed issuer URLs.
	// If empty, all issuers are accepted (not recommended for production).
	TrustedIssuers []string

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

// VerifyWithOptions performs badge verification with the specified options.
// Implements RFC-002 §8.1 verification flow.
func (v *Verifier) VerifyWithOptions(ctx context.Context, token string, opts VerifyOptions) (*VerifyResult, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}

	result := &VerifyResult{
		Mode: opts.Mode,
	}

	// Step 1: Parse JWS
	jwsObj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return nil, WrapError(ErrCodeMalformed, "failed to parse JWS", err)
	}

	// Step 2: Extract Claims (Unverified) to get Issuer
	unsafePayload := jwsObj.UnsafePayloadWithoutVerification()
	var claims Claims
	if err := json.Unmarshal(unsafePayload, &claims); err != nil {
		return nil, WrapError(ErrCodeMalformed, "failed to unmarshal claims", err)
	}

	// Step 3: Validate structure
	if err := v.validateStructure(jwsObj, &claims); err != nil {
		return nil, err
	}

	// Step 4: Fetch CA public key
	pubKey, err := v.registry.GetPublicKey(ctx, claims.Issuer)
	if err != nil {
		return nil, WrapError(ErrCodeIssuerUntrusted, fmt.Sprintf("failed to fetch public key for issuer %s", claims.Issuer), err)
	}

	// Step 5: Verify Signature
	payload, err := jwsObj.Verify(pubKey)
	if err != nil {
		return nil, WrapError(ErrCodeSignatureInvalid, "signature verification failed", err)
	}

	// Re-unmarshal verified payload to ensure integrity
	var verifiedClaims Claims
	if err := json.Unmarshal(payload, &verifiedClaims); err != nil {
		return nil, WrapError(ErrCodeMalformed, "failed to unmarshal verified claims", err)
	}

	// Step 6: Validate claims
	if err := v.validateClaims(&verifiedClaims, opts, now()); err != nil {
		return nil, err
	}

	// Step 7: Check revocation (if not skipped)
	if !opts.SkipRevocationCheck {
		if err := v.checkRevocation(ctx, &verifiedClaims, opts); err != nil {
			return nil, err
		}
	}

	// Step 8: Check agent status (if not skipped)
	if !opts.SkipAgentStatusCheck {
		if err := v.checkAgentStatus(ctx, &verifiedClaims, opts, result); err != nil {
			return nil, err
		}
	}

	result.Claims = &verifiedClaims
	return result, nil
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

	// Validate subject is a valid did:web
	_, err := did.Parse(claims.Subject)
	if err != nil {
		return WrapError(ErrCodeClaimsInvalid, "invalid subject DID", err)
	}

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
func (v *Verifier) validateClaims(claims *Claims, opts VerifyOptions, now time.Time) error {
	nowUnix := now.Unix()

	// Step 6a: exp > current_time (not expired)
	if claims.Expiry <= nowUnix {
		return NewError(ErrCodeExpired, fmt.Sprintf("badge expired at %s", time.Unix(claims.Expiry, 0).Format(time.RFC3339)))
	}

	// Step 6b: iat <= current_time (not issued in future)
	if claims.IssuedAt > nowUnix {
		return NewError(ErrCodeNotYetValid, fmt.Sprintf("badge not valid until %s", time.Unix(claims.IssuedAt, 0).Format(time.RFC3339)))
	}

	// Step 6c: Issuer in trusted issuer list
	if len(opts.TrustedIssuers) > 0 {
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

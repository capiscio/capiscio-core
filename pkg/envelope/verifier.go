package envelope

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"
)

// KeyResolver resolves a DID and key ID to a public key.
// For did:key: extracts the public key from the DID itself (no network call).
// For did:web: fetches the DID document and extracts the key by fragment.
type KeyResolver func(ctx context.Context, didStr string, kid string) (crypto.PublicKey, error)

// DefaultKeyResolver resolves did:key identifiers to Ed25519 public keys.
// It does not support did:web (returns an error for non-did:key identifiers).
func DefaultKeyResolver(_ context.Context, didStr string, _ string) (crypto.PublicKey, error) {
	parsed, err := did.Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID %q: %w", didStr, err)
	}
	if !parsed.IsKeyDID() {
		return nil, fmt.Errorf("DID %q is not a did:key identifier; did:web resolution not yet supported", didStr)
	}
	pubKey := parsed.GetPublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("failed to extract public key from DID %q", didStr)
	}
	return pubKey, nil
}

// VerifyOptions configures envelope verification.
type VerifyOptions struct {
	// TrustedIssuers restricts which badge issuers are accepted.
	// Passed through to badge verification.
	TrustedIssuers []string

	// EnforcementMode is the PEP's configured enforcement mode.
	EnforcementMode EnforcementMode

	// MaxPayloadSize is the max envelope payload in bytes. Default: 8192.
	MaxPayloadSize int

	// Now overrides time.Now() for testing.
	Now func() time.Time

	// SkipBadgeVerification skips badge verification steps.
	// For testing only — never use in production.
	SkipBadgeVerification bool
}

func (o *VerifyOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *VerifyOptions) maxPayloadSize() int {
	if o.MaxPayloadSize > 0 {
		return o.MaxPayloadSize
	}
	return MaxPayloadSize
}

// VerifyResult contains the outcome of envelope verification.
type VerifyResult struct {
	// Payload is the verified envelope payload.
	Payload *Payload

	// IssuerBadge is the verified issuer badge result (nil if badge verification skipped).
	IssuerBadge *badge.VerifyResult

	// SubjectBadge is the verified subject badge result (nil for root or if skipped).
	SubjectBadge *badge.VerifyResult

	// EffectiveMode is the enforcement mode after escalation.
	EffectiveMode EnforcementMode

	// ChainDepth is 0 for root envelopes, N for the Nth delegation.
	ChainDepth int
}

// ChainVerifyResult contains the outcome of chain verification.
type ChainVerifyResult struct {
	// Links contains the verification result for each envelope in the chain.
	Links []*VerifyResult

	// RootCapability is the capability class from the root envelope.
	RootCapability string

	// LeafCapability is the capability class from the leaf (last) envelope.
	LeafCapability string

	// TotalDepth is the number of delegation hops in the chain.
	TotalDepth int
}

// Verifier verifies Authority Envelopes per RFC-008 §9.2.
type Verifier struct {
	// BadgeVerifier verifies trust badges (RFC-002).
	BadgeVerifier *badge.Verifier

	// KeyResolver resolves DIDs to public keys.
	KeyResolver KeyResolver
}

// VerifyEnvelope verifies a single Authority Envelope.
//
// It implements the RFC-008 §9.2 verification sequence:
//  1. Parse and validate envelope structure
//  2. Verify issuer badge (RFC-002) — if not skipped
//  3. Resolve signing key from issuer DID
//  4. Verify JWS signature
//  5. Check temporal validity
//  6. Verify badge JTI bindings
//  7. Apply enforcement mode escalation
//
// Steps 5 (invocation evidence, RFC-004) and 9 (PDP query, RFC-005) from the spec
// are not implemented — those RFCs are not yet available.
func (v *Verifier) VerifyEnvelope(
	ctx context.Context,
	envelopeJWS string,
	issuerBadgeJWS string,
	subjectBadgeJWS string,
	opts VerifyOptions,
) (*VerifyResult, error) {
	// Step 1: Parse envelope
	maxSize := opts.maxPayloadSize()
	jws, err := jose.ParseSigned(envelopeJWS, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256, jose.ES384})
	if err != nil {
		return nil, NewError(ErrCodeMalformed, fmt.Sprintf("failed to parse JWS: %v", err))
	}

	// Check typ header
	if len(jws.Signatures) == 0 {
		return nil, NewError(ErrCodeMalformed, "no signatures found")
	}
	typ := ""
	if t, ok := jws.Signatures[0].Protected.ExtraHeaders["typ"].(string); ok {
		typ = t
	} else if t, ok := jws.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string); ok {
		typ = t
	}
	if typ != HeaderType {
		return nil, NewError(ErrCodeMalformed,
			fmt.Sprintf("invalid typ header: expected %q, got %q", HeaderType, typ))
	}

	// Step 2: Verify issuer badge
	var issuerBadgeResult *badge.VerifyResult
	if !opts.SkipBadgeVerification && issuerBadgeJWS != "" {
		if v.BadgeVerifier == nil {
			return nil, fmt.Errorf("badge verifier is required for badge verification")
		}
		badgeOpts := badge.VerifyOptions{
			TrustedIssuers:       opts.TrustedIssuers,
			AcceptSelfSigned:     true, // self-signed badges can issue envelopes
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: false,
		}
		issuerBadgeResult, err = v.BadgeVerifier.VerifyWithOptions(ctx, issuerBadgeJWS, badgeOpts)
		if err != nil {
			return nil, WrapError(ErrCodeBadgeBindingFailed, "issuer badge verification failed", err)
		}
	}

	// Step 3: Resolve signing key from issuer DID
	kid := ""
	if k, ok := jws.Signatures[0].Protected.ExtraHeaders["kid"].(string); ok {
		kid = k
	} else if k, ok := jws.Signatures[0].Protected.ExtraHeaders[jose.HeaderKey("kid")].(string); ok {
		kid = k
	}

	// Extract unverified payload to get issuer_did for key resolution
	unverifiedPayload := jws.UnsafePayloadWithoutVerification()
	if len(unverifiedPayload) > maxSize {
		return nil, NewError(ErrCodePayloadTooLarge,
			fmt.Sprintf("payload size %d exceeds maximum %d", len(unverifiedPayload), maxSize))
	}

	var unverifiedClaims Payload
	if err := json.Unmarshal(unverifiedPayload, &unverifiedClaims); err != nil {
		return nil, NewError(ErrCodeMalformed, fmt.Sprintf("failed to unmarshal payload: %v", err))
	}

	resolver := v.KeyResolver
	if resolver == nil {
		resolver = DefaultKeyResolver
	}

	pubKey, err := resolver(ctx, unverifiedClaims.IssuerDID, kid)
	if err != nil {
		return nil, WrapError(ErrCodeKeyNotBound,
			fmt.Sprintf("failed to resolve key for DID %q", unverifiedClaims.IssuerDID), err)
	}

	// Step 4: Verify JWS signature
	verifiedPayload, err := jws.Verify(pubKey)
	if err != nil {
		return nil, NewError(ErrCodeSignatureInvalid, fmt.Sprintf("signature verification failed: %v", err))
	}

	var payload Payload
	if err := json.Unmarshal(verifiedPayload, &payload); err != nil {
		return nil, NewError(ErrCodeMalformed, fmt.Sprintf("failed to unmarshal verified payload: %v", err))
	}

	if err := payload.Validate(); err != nil {
		return nil, err
	}

	// Step 5: Temporal validity
	now := opts.now()
	nowUnix := now.Unix()
	if nowUnix >= payload.ExpiresAt {
		return nil, NewError(ErrCodeExpired,
			fmt.Sprintf("envelope expired at %d, current time is %d", payload.ExpiresAt, nowUnix))
	}
	if payload.IssuedAt > nowUnix {
		return nil, NewError(ErrCodeNotYetValid,
			fmt.Sprintf("envelope issued_at %d is in the future (current time %d)", payload.IssuedAt, nowUnix))
	}

	// Step 6: Badge JTI binding
	if issuerBadgeResult != nil {
		if payload.IssuerBadgeJTI != issuerBadgeResult.Claims.JTI {
			return nil, NewError(ErrCodeBadgeBindingFailed,
				fmt.Sprintf("issuer_badge_jti %q does not match presented badge jti %q",
					payload.IssuerBadgeJTI, issuerBadgeResult.Claims.JTI))
		}
	}

	var subjectBadgeResult *badge.VerifyResult
	if !opts.SkipBadgeVerification && payload.SubjectBadgeJTI != nil && subjectBadgeJWS != "" {
		if v.BadgeVerifier == nil {
			return nil, fmt.Errorf("badge verifier is required for subject badge verification")
		}
		badgeOpts := badge.VerifyOptions{
			TrustedIssuers:       opts.TrustedIssuers,
			AcceptSelfSigned:     true,
			SkipRevocationCheck:  false,
			SkipAgentStatusCheck: false,
		}
		subjectBadgeResult, err = v.BadgeVerifier.VerifyWithOptions(ctx, subjectBadgeJWS, badgeOpts)
		if err != nil {
			return nil, WrapError(ErrCodeBadgeBindingFailed, "subject badge verification failed", err)
		}
		if *payload.SubjectBadgeJTI != subjectBadgeResult.Claims.JTI {
			return nil, NewError(ErrCodeBadgeBindingFailed,
				fmt.Sprintf("subject_badge_jti %q does not match presented badge jti %q",
					*payload.SubjectBadgeJTI, subjectBadgeResult.Claims.JTI))
		}
	}

	// Step 7: Enforcement mode escalation
	effectiveMode := opts.EnforcementMode
	if payload.EnforcementModeMin != nil {
		minMode, err := ParseEnforcementMode(*payload.EnforcementModeMin)
		if err != nil {
			return nil, err
		}
		effectiveMode = Escalate(effectiveMode, minMode)
	}

	return &VerifyResult{
		Payload:       &payload,
		IssuerBadge:   issuerBadgeResult,
		SubjectBadge:  subjectBadgeResult,
		EffectiveMode: effectiveMode,
	}, nil
}

// VerifyChain verifies a full delegation chain of Authority Envelopes.
// envelopeJWSs must be ordered root→leaf.
// badgeJWSMap maps DIDs to their current badge JWS strings.
func (v *Verifier) VerifyChain(
	ctx context.Context,
	envelopeJWSs []string,
	badgeJWSMap map[string]string,
	opts VerifyOptions,
) (*ChainVerifyResult, error) {
	if len(envelopeJWSs) == 0 {
		return nil, NewError(ErrCodeMalformed, "chain is empty")
	}

	// First pass: parse all tokens to validate structure
	tokens := make(Chain, 0, len(envelopeJWSs))
	for i, jws := range envelopeJWSs {
		token, err := ParseToken(jws)
		if err != nil {
			return nil, WrapError(ErrCodeChainBroken,
				fmt.Sprintf("failed to parse envelope at position %d", i), err)
		}
		tokens = append(tokens, token)
	}

	// Validate chain structural integrity (hash links, narrowing, DID chain)
	if err := ValidateChainIntegrity(tokens); err != nil {
		return nil, err
	}

	// Verify each envelope individually
	links := make([]*VerifyResult, 0, len(envelopeJWSs))
	for i, jwsStr := range envelopeJWSs {
		payload := tokens[i].Payload

		issuerBadge := badgeJWSMap[payload.IssuerDID]
		subjectBadge := ""
		if payload.SubjectBadgeJTI != nil {
			subjectBadge = badgeJWSMap[payload.SubjectDID]
		}

		result, err := v.VerifyEnvelope(ctx, jwsStr, issuerBadge, subjectBadge, opts)
		if err != nil {
			return nil, WrapError(ErrCodeChainBroken,
				fmt.Sprintf("verification failed at chain position %d", i), err)
		}
		result.ChainDepth = i
		links = append(links, result)
	}

	return &ChainVerifyResult{
		Links:          links,
		RootCapability: tokens[0].Payload.CapabilityClass,
		LeafCapability: tokens[len(tokens)-1].Payload.CapabilityClass,
		TotalDepth:     len(tokens) - 1,
	}, nil
}

// Package envelope implements RFC-008 Delegated Authority Envelopes.
//
// Authority Envelopes are signed JWS tokens that encode delegation of
// capabilities between agents. Envelopes form chains linked by
// parent_authority_hash, with monotonic narrowing enforced across four
// dimensions: capability class, temporal bounds, delegation depth, and
// constraints.
package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

const (
	// HeaderType is the JWS typ header value for Authority Envelopes.
	HeaderType = "capiscio-authority-envelope+jws"

	// MaxPayloadSize is the recommended maximum payload size (8 KB).
	MaxPayloadSize = 8192
)

// Payload is the Authority Envelope JWT claims payload per RFC-008 §5.4.
type Payload struct {
	// EnvelopeID is a unique identifier for this delegation grant (UUID v7).
	EnvelopeID string `json:"envelope_id"`

	// IssuerDID is the DID of the authority granter.
	IssuerDID string `json:"issuer_did"`

	// SubjectDID is the DID of the authority receiver.
	SubjectDID string `json:"subject_did"`

	// TxnID is the RFC-004 transaction identifier.
	TxnID string `json:"txn_id"`

	// ParentAuthorityHash is the SHA-256 hex hash of the parent envelope's JWS.
	// nil for root envelopes.
	ParentAuthorityHash *string `json:"parent_authority_hash"`

	// CapabilityClass is the dot-delimited capability namespace (e.g. "tools.database.read").
	CapabilityClass string `json:"capability_class"`

	// Constraints is an opaque key-value object interpreted by the PDP.
	Constraints map[string]any `json:"constraints"`

	// DelegationDepthRemaining is the remaining delegation hops (≥0).
	// MUST be decremented by ≥1 in each derived envelope.
	DelegationDepthRemaining int `json:"delegation_depth_remaining"`

	// EnforcementModeMin is the minimum enforcement mode the issuer requires.
	// nil means no issuer minimum.
	EnforcementModeMin *string `json:"enforcement_mode_min"`

	// IssuedAt is the Unix timestamp (seconds) of creation.
	IssuedAt int64 `json:"issued_at"`

	// ExpiresAt is the Unix timestamp (seconds) of expiration.
	ExpiresAt int64 `json:"expires_at"`

	// IssuerBadgeJTI is the jti of the issuer's current RFC-002 Trust Badge.
	IssuerBadgeJTI string `json:"issuer_badge_jti"`

	// SubjectBadgeJTI is the jti of the subject's current RFC-002 Trust Badge.
	// nil for root envelopes when subject has no badge session yet.
	SubjectBadgeJTI *string `json:"subject_badge_jti"`
}

// Token wraps a parsed envelope with its raw JWS string.
type Token struct {
	// Raw is the JWS Compact Serialization string.
	Raw string

	// Payload is the decoded envelope payload.
	Payload *Payload
}

// ComputeHash returns the SHA-256 hex-lowercase hash of a JWS compact string.
// Used as parent_authority_hash for derived envelopes (RFC-008 §6.3).
func ComputeHash(jwsCompact string) string {
	h := sha256.Sum256([]byte(jwsCompact))
	return hex.EncodeToString(h[:])
}

// Validate checks that the payload has all required fields and valid values.
func (p *Payload) Validate() error {
	if p.EnvelopeID == "" {
		return NewError(ErrCodeMalformed, "envelope_id is required")
	}
	if p.IssuerDID == "" {
		return NewError(ErrCodeMalformed, "issuer_did is required")
	}
	if p.SubjectDID == "" {
		return NewError(ErrCodeMalformed, "subject_did is required")
	}
	if p.TxnID == "" {
		return NewError(ErrCodeMalformed, "txn_id is required")
	}
	if err := ValidateCapabilityClass(p.CapabilityClass); err != nil {
		return err
	}
	if p.Constraints == nil {
		return NewError(ErrCodeMalformed, "constraints is required (use empty object)")
	}
	if p.DelegationDepthRemaining < 0 {
		return NewError(ErrCodeMalformed, "delegation_depth_remaining must be >= 0")
	}
	if p.EnforcementModeMin != nil {
		if _, err := ParseEnforcementMode(*p.EnforcementModeMin); err != nil {
			return err
		}
	}
	if p.IssuedAt <= 0 {
		return NewError(ErrCodeMalformed, "issued_at is required")
	}
	if p.ExpiresAt <= 0 {
		return NewError(ErrCodeMalformed, "expires_at is required")
	}
	if p.ExpiresAt <= p.IssuedAt {
		return NewError(ErrCodeMalformed, "expires_at must be after issued_at")
	}
	if p.IssuerBadgeJTI == "" {
		return NewError(ErrCodeMalformed, "issuer_badge_jti is required")
	}
	return nil
}

// IsRoot returns true if this is a root envelope (no parent).
func (p *Payload) IsRoot() bool {
	return p.ParentAuthorityHash == nil
}

// ParseToken parses a JWS compact string into a Token without verifying the signature.
// This is useful for inspection. Use Verifier.VerifyEnvelope for full verification.
func ParseToken(jwsCompact string) (*Token, error) {
	jws, err := jose.ParseSigned(jwsCompact, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256, jose.ES384})
	if err != nil {
		return nil, NewError(ErrCodeMalformed, fmt.Sprintf("failed to parse JWS: %v", err))
	}

	// Check typ header
	headers := jws.Signatures
	if len(headers) == 0 {
		return nil, NewError(ErrCodeMalformed, "no signatures found")
	}
	typ := ""
	if t, ok := headers[0].Protected.ExtraHeaders["typ"].(string); ok {
		typ = t
	} else if t, ok := headers[0].Protected.ExtraHeaders[jose.HeaderType].(string); ok {
		typ = t
	}
	if typ != HeaderType {
		return nil, NewError(ErrCodeMalformed, fmt.Sprintf("invalid typ header: expected %q, got %q", HeaderType, typ))
	}

	// Extract unverified payload
	payloadBytes := jws.UnsafePayloadWithoutVerification()
	if len(payloadBytes) > MaxPayloadSize {
		return nil, NewError(ErrCodePayloadTooLarge, fmt.Sprintf("payload size %d exceeds maximum %d", len(payloadBytes), MaxPayloadSize))
	}

	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, NewError(ErrCodeMalformed, fmt.Sprintf("failed to unmarshal payload: %v", err))
	}

	return &Token{
		Raw:     jwsCompact,
		Payload: &payload,
	}, nil
}

// String returns a human-readable summary of the envelope payload.
func (p *Payload) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Envelope %s\n", p.EnvelopeID)
	fmt.Fprintf(&b, "  Issuer:     %s\n", p.IssuerDID)
	fmt.Fprintf(&b, "  Subject:    %s\n", p.SubjectDID)
	fmt.Fprintf(&b, "  Capability: %s\n", p.CapabilityClass)
	fmt.Fprintf(&b, "  Depth:      %d\n", p.DelegationDepthRemaining)
	if p.ParentAuthorityHash != nil {
		fmt.Fprintf(&b, "  Parent:     %s\n", *p.ParentAuthorityHash)
	} else {
		fmt.Fprintf(&b, "  Parent:     (root)\n")
	}
	return b.String()
}

package badge

import (
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims represents the JWT claims payload for a CapiscIO Trust Badge.
// See RFC-002: Trust Badge Specification.
type Claims struct {
	// JTI is the unique Badge ID (UUID v4). Used for revocation and audit.
	JTI string `json:"jti"`

	// Issuer is the CA that signed the Badge (e.g., "https://registry.capisc.io").
	Issuer string `json:"iss"`

	// Subject is the agent's DID. MUST be a valid did:web identifier.
	// Format: did:web:registry.capisc.io:agents:<agent-id>
	Subject string `json:"sub"`

	// Audience is the list of trust domains/services where Badge is valid.
	// Optional. If present, verifiers MUST check their identity is included.
	Audience []string `json:"aud,omitempty"`

	// IssuedAt is the timestamp when the badge was issued (Unix timestamp).
	IssuedAt int64 `json:"iat"`

	// Expiry is the timestamp when the badge expires (Unix timestamp).
	Expiry int64 `json:"exp"`

	// NotBefore is the timestamp before which the badge MUST NOT be accepted.
	// Optional. Per RFC-002 §4.3.1.
	NotBefore int64 `json:"nbf,omitempty"`

	// IAL is the Identity Assurance Level. REQUIRED per RFC-002 §4.3.2.
	// "0" = Account-attested (IAL-0), "1" = Proof of Possession (IAL-1).
	IAL string `json:"ial"`

	// Key is the public key of the subject, embedded for offline verification.
	// REQUIRED in production. MAY be omitted in non-production environments.
	Key *jose.JSONWebKey `json:"key,omitempty"`

	// CNF is the confirmation claim per RFC 7800.
	// When present, binds the badge to a specific key holder.
	// Used for Proof of Possession (PoP) badges (RFC-002 §7.2.2, RFC-005).
	CNF *ConfirmationClaim `json:"cnf,omitempty"`

	// PoPChallengeID is a reference to the PoP challenge used during issuance.
	// Optional. Provides audit trail for PoP-issued badges (RFC-002 §4.3.3).
	PoPChallengeID string `json:"pop_challenge_id,omitempty"`

	// AgentCardHash is the SHA-256 hash of the canonical AgentCard at issuance.
	// Optional. Enables verifiers to detect AgentCard drift (RFC-002 §4.3.3).
	AgentCardHash string `json:"agent_card_hash,omitempty"`

	// DIDDocHash is the SHA-256 hash of the DID Document at issuance.
	// Optional. Enables verifiers to detect key rotation (RFC-002 §4.3.3).
	DIDDocHash string `json:"did_doc_hash,omitempty"`

	// VC contains the Verifiable Credential data.
	VC VerifiableCredential `json:"vc"`
}

// ConfirmationClaim represents the cnf claim per RFC 7800.
// Used to bind a badge to a specific key for Proof of Possession.
type ConfirmationClaim struct {
	// KID is the key ID referencing the key in the DID Document.
	// This is the primary mechanism for PoP badges.
	KID string `json:"kid,omitempty"`

	// JWK is the full JWK of the confirmation key (alternative to kid).
	JWK *jose.JSONWebKey `json:"jwk,omitempty"`

	// JKT is the JWK thumbprint (SHA-256) of the confirmation key.
	JKT string `json:"jkt,omitempty"`
}

// AgentID extracts the agent ID from the Subject DID.
// For did:web:registry.capisc.io:agents:my-agent-001, returns "my-agent-001".
// Returns empty string if the DID format is invalid.
func (c *Claims) AgentID() string {
	// did:web:registry.capisc.io:agents:my-agent-001
	// Split by ":" and find "agents" segment, then return the next segment
	parts := strings.Split(c.Subject, ":")
	for i, part := range parts {
		if part == "agents" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// IsExpired returns true if the badge has expired.
func (c *Claims) IsExpired() bool {
	return time.Now().Unix() >= c.Expiry
}

// IsNotYetValid returns true if the badge's iat is in the future.
func (c *Claims) IsNotYetValid() bool {
	return time.Now().Unix() < c.IssuedAt
}

// ExpiresAt returns the expiry time as a time.Time.
func (c *Claims) ExpiresAt() time.Time {
	return time.Unix(c.Expiry, 0)
}

// IssuedAtTime returns the issued-at time as a time.Time.
func (c *Claims) IssuedAtTime() time.Time {
	return time.Unix(c.IssuedAt, 0)
}

// TrustLevel returns the trust level from the VC credential subject.
// Returns "1", "2", or "3", or empty string if not set.
func (c *Claims) TrustLevel() string {
	return c.VC.CredentialSubject.Level
}

// Domain returns the domain from the VC credential subject.
func (c *Claims) Domain() string {
	return c.VC.CredentialSubject.Domain
}

// AssuranceLevel returns the identity assurance level of the badge.
// Per RFC-002 §7.2.1:
// - IAL-0: Account-attested bearer badge
// - IAL-1: Proof of Possession badge
// The IAL claim is authoritative; cnf is supporting evidence.
func (c *Claims) AssuranceLevel() string {
	// If IAL claim is explicitly set, use it
	if c.IAL == "1" {
		return "IAL-1"
	}
	if c.IAL == "0" {
		return "IAL-0"
	}
	// Fallback for legacy badges without IAL claim: check cnf
	if c.CNF != nil && (c.CNF.KID != "" || c.CNF.JWK != nil || c.CNF.JKT != "") {
		return "IAL-1"
	}
	return "IAL-0"
}

// HasProofOfPossession returns true if this is a PoP-issued badge.
func (c *Claims) HasProofOfPossession() bool {
	return c.AssuranceLevel() == "IAL-1"
}

// VerifiableCredential represents the simplified VC object.
type VerifiableCredential struct {
	// Type is the JSON-LD type(s) of the credential.
	// MUST include "VerifiableCredential" and "AgentIdentity".
	Type []string `json:"type"`

	// CredentialSubject contains the claims about the subject.
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

// CredentialSubject contains the specific claims.
type CredentialSubject struct {
	// Domain is the agent's home domain.
	// MUST be validated according to the trust level's requirements.
	Domain string `json:"domain,omitempty"`

	// Level indicates the trust level: "1" (DV), "2" (OV), or "3" (EV).
	Level string `json:"level,omitempty"`
}

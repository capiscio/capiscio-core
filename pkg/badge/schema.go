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

	// Key is the public key of the subject, embedded for offline verification.
	// REQUIRED in production. MAY be omitted in non-production environments.
	Key *jose.JSONWebKey `json:"key,omitempty"`

	// VC contains the Verifiable Credential data.
	VC VerifiableCredential `json:"vc"`
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

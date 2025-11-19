package badge

import "github.com/go-jose/go-jose/v4"

// Claims represents the JWT claims payload for a CapiscIO Trust Badge.
// It follows the structure defined in the Minimal Authority Stack plan.
type Claims struct {
	// Issuer is the entity that issued the badge (e.g., "https://registry.capisc.io").
	Issuer string `json:"iss"`

	// Subject is the unique identifier of the Agent (e.g., "did:capiscio:agent:12345").
	Subject string `json:"sub"`

	// IssuedAt is the timestamp when the badge was issued (Unix timestamp).
	IssuedAt int64 `json:"iat"`

	// Expiry is the timestamp when the badge expires (Unix timestamp).
	Expiry int64 `json:"exp"`

	// Key is the public key of the subject, embedded for offline verification.
	Key *jose.JSONWebKey `json:"key,omitempty"`

	// VC contains the Verifiable Credential data.
	VC VerifiableCredential `json:"vc"`
}

// VerifiableCredential represents the simplified VC object.
type VerifiableCredential struct {
	// Type is the JSON-LD type(s) of the credential.
	Type []string `json:"type"`

	// CredentialSubject contains the claims about the subject.
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

// CredentialSubject contains the specific claims.
type CredentialSubject struct {
	// Domain is the security domain of the agent (e.g., "finance.internal").
	Domain string `json:"domain,omitempty"`

	// Level indicates the trust level (e.g., "1" = Domain Validated).
	Level string `json:"level,omitempty"`
}

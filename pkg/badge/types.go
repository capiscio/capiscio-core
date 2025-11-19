package badge

import (
	"time"
)

// TrustBadge represents a signed identity document for an Agent.
// It serves as the "Passport" in the CapiscIO Trust System.
type TrustBadge struct {
	// Issuer is the entity that issued the badge (e.g., "did:web:registry.capisc.io").
	Issuer string `json:"iss"`

	// Subject is the unique identifier of the Agent (e.g., "did:web:agent.example.com").
	Subject string `json:"sub"`

	// IssuedAt is the timestamp when the badge was issued.
	IssuedAt time.Time `json:"iat"`

	// Expiry is the timestamp when the badge expires.
	Expiry time.Time `json:"exp"`

	// Capabilities defines the authorized scopes/actions for this agent.
	Capabilities []string `json:"cap,omitempty"`

	// Signature contains the cryptographic proof of the badge's validity.
	Signature *BadgeSignature `json:"proof,omitempty"`
}

// BadgeSignature represents the cryptographic signature of the TrustBadge.
type BadgeSignature struct {
	// Type is the signature algorithm used (e.g., "Ed25519Signature2020").
	Type string `json:"type"`

	// Created is the timestamp when the signature was created.
	Created time.Time `json:"created"`

	// VerificationMethod is the URI of the public key used to verify the signature.
	VerificationMethod string `json:"verificationMethod"`

	// Value is the actual signature string (Base64 encoded).
	Value string `json:"jws"` // Using JWS compact serialization
}

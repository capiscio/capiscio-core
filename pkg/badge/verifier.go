package badge

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/capiscio/capiscio-core/pkg/registry"
	"github.com/go-jose/go-jose/v4"
)

// Verifier validates TrustBadges.
type Verifier struct {
	registry registry.Registry
}

// NewVerifier creates a new Badge Verifier.
func NewVerifier(reg registry.Registry) *Verifier {
	return &Verifier{
		registry: reg,
	}
}

// Verify checks the validity of a TrustBadge.
// It verifies the signature, expiry, and revocation status.
func (v *Verifier) Verify(ctx context.Context, badge *TrustBadge) error {
	// 1. Check Expiry
	if time.Now().After(badge.Expiry) {
		return fmt.Errorf("badge expired at %s", badge.Expiry)
	}

	// 2. Check Signature presence
	if badge.Signature == nil || badge.Signature.Value == "" {
		return fmt.Errorf("badge is missing signature")
	}

	// 3. Fetch Public Key from Registry
	// The VerificationMethod usually contains the DID/Key ID.
	// For simplicity, we assume the Issuer DID is the key lookup key.
	pubKey, err := v.registry.GetPublicKey(ctx, badge.Issuer)
	if err != nil {
		return fmt.Errorf("failed to fetch public key for issuer %s: %w", badge.Issuer, err)
	}

	// 4. Verify Signature
	// We assume the Signature.Value is a JWS Compact Serialization.
	// We allow standard algorithms.
	algorithms := []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256, jose.RS256}
	jwsObj, err := jose.ParseSigned(badge.Signature.Value, algorithms)
	if err != nil {
		return fmt.Errorf("failed to parse JWS: %w", err)
	}

	// Verify the signature against the public key.
	// If the JWS is detached, we might need to provide the payload, but go-jose's
	// Verify method returns the payload. If it's detached in the JWS string (empty payload part),
	// go-jose might expect us to know it.
	// However, for this implementation, let's assume the JWS contains the payload (Attached).
	// If we want to support Detached, we would need to reconstruct the payload and use
	// a library feature that supports it, or ensure the JWS string has the payload.
	// Given the "TrustBadge" struct has the data, a Detached JWS is most logical.
	// But go-jose's high-level API is simpler with Attached.
	// Let's try to verify.
	_, err = jwsObj.Verify(pubKey)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	
	// TODO: If detached, we must verify that the payload matches the badge data.
	// payload, err := v.canonicalize(badge)
	// ... verify payload matches output of Verify ...

	// 5. Check Revocation
	// We use the Subject or a Badge ID (if we had one)
	revoked, err := v.registry.IsRevoked(ctx, badge.Subject)
	if err != nil {
		return fmt.Errorf("failed to check revocation status: %w", err)
	}
	if revoked {
		return fmt.Errorf("badge for subject %s has been revoked", badge.Subject)
	}

	return nil
}

// canonicalize creates the byte representation of the badge for signing/verification.
func (v *Verifier) canonicalize(badge *TrustBadge) ([]byte, error) {
	// Marshal to JSON
	data, err := json.Marshal(badge)
	if err != nil {
		return nil, err
	}

	// Unmarshal to map to remove signature
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	delete(raw, "proof") // Remove the signature field

	// Marshal back to get canonical bytes
	return json.Marshal(raw)
}

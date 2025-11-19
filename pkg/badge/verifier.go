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

// Verify checks the validity of a TrustBadge JWS token.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	// 1. Parse JWS
	jwsObj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	// 2. Extract Claims (Unverified) to get Issuer
	unsafePayload := jwsObj.UnsafePayloadWithoutVerification()
	var claims Claims
	if err := json.Unmarshal(unsafePayload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	if claims.Issuer == "" {
		return nil, fmt.Errorf("missing issuer claim")
	}

	// 3. Fetch Public Key from Registry
	pubKey, err := v.registry.GetPublicKey(ctx, claims.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key for issuer %s: %w", claims.Issuer, err)
	}

	// 4. Verify Signature
	payload, err := jwsObj.Verify(pubKey)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 5. Re-unmarshal verified payload to ensure integrity
	var verifiedClaims Claims
	if err := json.Unmarshal(payload, &verifiedClaims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verified claims: %w", err)
	}

	// 6. Check Expiry
	now := time.Now().Unix()
	if verifiedClaims.Expiry < now {
		return nil, fmt.Errorf("badge expired at %d (now: %d)", verifiedClaims.Expiry, now)
	}

	return &verifiedClaims, nil
}

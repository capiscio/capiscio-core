package badge

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// SignBadge creates a signed JWS token from the given claims using the private key.
// It defaults to EdDSA (Ed25519) signing.
func SignBadge(claims *BadgeClaims, privateKey crypto.PrivateKey) (string, error) {
	// 1. Create Signer
	// We use EdDSA (Ed25519) as the primary algorithm.
	// Ideally, we should detect the key type, but for the Minimal Stack, we assume Ed25519.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// 2. Marshal Claims
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// 3. Sign
	jwsObj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	// 4. Serialize to Compact JWS
	token, err := jwsObj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWS: %w", err)
	}

	return token, nil
}

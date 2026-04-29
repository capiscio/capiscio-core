package envelope

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// SignEnvelope creates a signed Authority Envelope JWS token.
// privateKey must be an ed25519.PrivateKey.
// keyID is the DID key reference for the JWS kid header (e.g., "did:key:z6Mk...#key-1").
func SignEnvelope(payload *Payload, privateKey crypto.PrivateKey, keyID string) (string, error) {
	if err := payload.Validate(); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	opts := &jose.SignerOptions{}
	opts.WithType(HeaderType)
	opts.WithHeader("kid", keyID)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	jwsObj, err := signer.Sign(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	token, err := jwsObj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWS: %w", err)
	}

	return token, nil
}

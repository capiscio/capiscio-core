package registry

import (
	"context"
	"crypto"
)

// Registry defines the interface for the CapiscIO Trust Registry.
// It is responsible for resolving trusted public keys for Issuers.
type Registry interface {
	// GetPublicKey fetches the public key for a given Issuer DID/URI.
	// Returns the public key and any error encountered.
	GetPublicKey(ctx context.Context, issuerDID string) (crypto.PublicKey, error)

	// IsRevoked checks if a specific Badge ID (or Subject) has been revoked.
	IsRevoked(ctx context.Context, badgeID string) (bool, error)
}

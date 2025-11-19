package registry

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// LocalRegistry implements Registry using a local file.
type LocalRegistry struct {
	KeyPath string

	mu        sync.RWMutex
	cachedKey crypto.PublicKey
}

// NewLocalRegistry creates a new LocalRegistry.
func NewLocalRegistry(path string) *LocalRegistry {
	return &LocalRegistry{KeyPath: path}
}

// GetPublicKey reads the key from the local file.
// It ignores the issuer argument for the MVP (trusts the local key for all).
func (r *LocalRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
	r.mu.RLock()
	if r.cachedKey != nil {
		r.mu.RUnlock()
		return r.cachedKey, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double check
	if r.cachedKey != nil {
		return r.cachedKey, nil
	}

	data, err := os.ReadFile(r.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read local key file: %w", err)
	}

	// Parse JWK
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse local JWK: %w", err)
	}

	r.cachedKey = jwk.Key
	return jwk.Key, nil
}

// IsRevoked checks if the ID is in the local blocklist (not implemented yet).
func (r *LocalRegistry) IsRevoked(ctx context.Context, id string) (bool, error) {
	return false, nil
}

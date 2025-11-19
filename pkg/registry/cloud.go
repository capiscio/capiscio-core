package registry

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// CloudRegistry implements Registry by fetching keys from a URL.
type CloudRegistry struct {
	RegistryURL string
	Client      *http.Client

	mu        sync.RWMutex
	cache     map[string]crypto.PublicKey
	cacheTime map[string]time.Time
}

// NewCloudRegistry creates a new CloudRegistry.
func NewCloudRegistry(url string) *CloudRegistry {
	return &CloudRegistry{
		RegistryURL: url,
		Client:      &http.Client{Timeout: 10 * time.Second},
		cache:       make(map[string]crypto.PublicKey),
		cacheTime:   make(map[string]time.Time),
	}
}

// GetPublicKey fetches the key from the Registry URL.
// It assumes the URL returns a single JWK for now (MVP).
func (r *CloudRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
	// Check cache
	r.mu.RLock()
	key, ok := r.cache[issuer]
	expiry, _ := r.cacheTime[issuer]
	r.mu.RUnlock()

	if ok && time.Now().Before(expiry) {
		return key, nil
	}

	// Fetch
	req, err := http.NewRequestWithContext(ctx, "GET", r.RegistryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	// Parse JWK
	var jwk jose.JSONWebKey
	if err := json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		return nil, fmt.Errorf("failed to decode JWK: %w", err)
	}

	r.mu.Lock()
	r.cache[issuer] = jwk.Key
	r.cacheTime[issuer] = time.Now().Add(5 * time.Minute) // Cache for 5 mins
	r.mu.Unlock()

	return jwk.Key, nil
}

// IsRevoked checks revocation (not implemented for MVP).
func (r *CloudRegistry) IsRevoked(ctx context.Context, id string) (bool, error) {
	return false, nil
}

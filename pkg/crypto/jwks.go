package crypto

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSFetcher handles fetching and caching of JSON Web Key Sets.
type JWKSFetcher interface {
	Fetch(ctx context.Context, url string) (*jose.JSONWebKeySet, error)
}

type cacheEntry struct {
	jwks      *jose.JSONWebKeySet
	expiresAt time.Time
}

// DefaultJWKSFetcher is the default implementation of JWKSFetcher.
type DefaultJWKSFetcher struct {
	client *http.Client
	cache  map[string]cacheEntry
	mu     sync.RWMutex
	ttl    time.Duration
}

// NewDefaultJWKSFetcher creates a new fetcher with a default HTTP client and 1 hour cache TTL.
func NewDefaultJWKSFetcher() *DefaultJWKSFetcher {
	return &DefaultJWKSFetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: make(map[string]cacheEntry),
		ttl:   1 * time.Hour,
	}
}

// SetTTL configures the cache time-to-live.
func (f *DefaultJWKSFetcher) SetTTL(ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ttl = ttl
}

// FlushCache clears all cached JWKS entries.
func (f *DefaultJWKSFetcher) FlushCache() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache = make(map[string]cacheEntry)
}

// Fetch retrieves the JWKS from the specified URL, using cache if available.
func (f *DefaultJWKSFetcher) Fetch(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {
	// 1. Check Cache
	f.mu.RLock()
	entry, found := f.cache[url]
	f.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.jwks, nil
	}

	// 2. Fetch from Network
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// 3. Update Cache
	f.mu.Lock()
	f.cache[url] = cacheEntry{
		jwks:      &jwks,
		expiresAt: time.Now().Add(f.ttl),
	}
	f.mu.Unlock()

	return &jwks, nil
}

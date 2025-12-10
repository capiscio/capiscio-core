// Package registry implements the Trust Registry interface for key retrieval.
package registry

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	expiry := r.cacheTime[issuer]
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
	defer func() { _ = resp.Body.Close() }()

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
// Deprecated: Use GetBadgeStatus instead.
func (r *CloudRegistry) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// GetBadgeStatus retrieves the status of a badge from the registry.
// Endpoint: GET {issuerURL}/v1/badges/{jti}/status
func (r *CloudRegistry) GetBadgeStatus(ctx context.Context, issuerURL string, jti string) (*BadgeStatus, error) {
	endpoint := fmt.Sprintf("%s/v1/badges/%s/status", issuerURL, url.PathEscape(jti))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch badge status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("badge not found: %s", jti)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var status BadgeStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode badge status: %w", err)
	}

	return &status, nil
}

// GetAgentStatus retrieves the status of an agent from the registry.
// Endpoint: GET {issuerURL}/v1/agents/{agentID}/status
func (r *CloudRegistry) GetAgentStatus(ctx context.Context, issuerURL string, agentID string) (*AgentStatus, error) {
	endpoint := fmt.Sprintf("%s/v1/agents/%s/status", issuerURL, url.PathEscape(agentID))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch agent status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var status AgentStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode agent status: %w", err)
	}

	return &status, nil
}

// SyncRevocations fetches revocations from the registry since the given time.
// Endpoint: GET {issuerURL}/v1/revocations?since={ISO8601}
func (r *CloudRegistry) SyncRevocations(ctx context.Context, issuerURL string, since time.Time) ([]Revocation, error) {
	endpoint := fmt.Sprintf("%s/v1/revocations?since=%s", issuerURL, url.QueryEscape(since.Format(time.RFC3339)))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch revocations: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var response struct {
		Revocations []Revocation `json:"revocations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode revocations: %w", err)
	}

	return response.Revocations, nil
}

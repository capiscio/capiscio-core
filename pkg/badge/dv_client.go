package badge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// DVClient is an HTTP client for Domain Validated badge orders (RFC-002 v1.2).
type DVClient struct {
	CAURL      string
	HTTPClient *http.Client
}

// NewDVClient creates a new DV client with a default HTTP client.
func NewDVClient(caURL string) *DVClient {
	return NewDVClientWithHTTPClient(caURL, nil)
}

// NewDVClientWithHTTPClient creates a new DV client with a custom HTTP client.
func NewDVClientWithHTTPClient(caURL string, httpClient *http.Client) *DVClient {
	if caURL == "" {
		caURL = DefaultCAURL
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	caURL = strings.TrimSuffix(caURL, "/")
	return &DVClient{
		CAURL:      caURL,
		HTTPClient: httpClient,
	}
}

// DVOrder represents a DV badge order.
type DVOrder struct {
	ID             string
	Domain         string
	ChallengeType  string
	ChallengeToken string
	Status         string
	ValidationURL  string
	DNSRecord      string
	ExpiresAt      time.Time
	FinalizedAt    *time.Time
}

// DVGrant represents a DV grant JWT.
type DVGrant struct {
	Grant     string
	ExpiresAt time.Time
}

// CreateOrder creates a new DV badge order.
func (c *DVClient) CreateOrder(ctx context.Context, domain, challengeType string, jwk *jose.JSONWebKey) (*DVOrder, error) {
	url := fmt.Sprintf("%s/v1/badges/dv/orders", c.CAURL)

	// Build request payload
	payload := map[string]interface{}{
		"domain":         domain,
		"challenge_type": challengeType,
		"jwk":            jwk,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "capiscio-core/2.2.0")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var apiResp struct {
		ID           string `json:"id"`
		Domain       string `json:"domain"`
		ChallengeType string `json:"challenge_type"`
		Status       string `json:"status"`
		Challenge    struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Token  string `json:"token"`
			Status string `json:"status"`
		} `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	order := &DVOrder{
		ID:             apiResp.ID,
		Domain:         apiResp.Domain,
		ChallengeType:  apiResp.ChallengeType,
		ChallengeToken: apiResp.Challenge.Token,
		Status:         apiResp.Status,
		ExpiresAt:      apiResp.ExpiresAt,
	}

	if apiResp.ChallengeType == "http-01" {
		order.ValidationURL = apiResp.Challenge.URL
	} else if apiResp.ChallengeType == "dns-01" {
		order.DNSRecord = apiResp.Challenge.Token
	}

	return order, nil
}

// GetOrder gets the status of a DV badge order.
func (c *DVClient) GetOrder(ctx context.Context, orderID string) (*DVOrder, error) {
	url := fmt.Sprintf("%s/v1/badges/dv/orders/%s", c.CAURL, orderID)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "capiscio-core/2.3.0")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var apiResp struct {
		ID            string     `json:"id"`
		Domain        string     `json:"domain"`
		ChallengeType string     `json:"challenge_type"`
		Status        string     `json:"status"`
		Challenge     struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Token  string `json:"token"`
			Status string `json:"status"`
		} `json:"challenge"`
		ExpiresAt   time.Time  `json:"expires_at"`
		FinalizedAt *time.Time `json:"finalized_at,omitempty"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	order := &DVOrder{
		ID:             apiResp.ID,
		Domain:         apiResp.Domain,
		ChallengeType:  apiResp.ChallengeType,
		ChallengeToken: apiResp.Challenge.Token,
		Status:         apiResp.Status,
		ExpiresAt:      apiResp.ExpiresAt,
		FinalizedAt:    apiResp.FinalizedAt,
	}

	if apiResp.ChallengeType == "http-01" {
		order.ValidationURL = apiResp.Challenge.URL
	} else if apiResp.ChallengeType == "dns-01" {
		order.DNSRecord = apiResp.Challenge.Token
	}

	return order, nil
}

// FinalizeOrder finalizes a DV badge order and receives a grant.
func (c *DVClient) FinalizeOrder(ctx context.Context, orderID string) (*DVGrant, error) {
	url := fmt.Sprintf("%s/v1/badges/dv/orders/%s/finalize", c.CAURL, orderID)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "capiscio-core/2.3.0")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var apiResp struct {
		Grant     string    `json:"grant"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &DVGrant{
		Grant:     apiResp.Grant,
		ExpiresAt: apiResp.ExpiresAt,
	}, nil
}

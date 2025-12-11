// Package badge provides badge client functionality for requesting badges from a CA.
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
)

// DefaultCAURL is the default CapiscIO Registry URL.
const DefaultCAURL = "https://registry.capisc.io"

// DefaultTTL is the default badge TTL per RFC-002.
const DefaultTTL = 5 * time.Minute

// Client is an HTTP client for requesting badges from a CA.
type Client struct {
	CAURL      string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new badge client.
func NewClient(caURL, apiKey string) *Client {
	if caURL == "" {
		caURL = DefaultCAURL
	}
	return &Client{
		CAURL:  strings.TrimSuffix(caURL, "/"),
		APIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RequestBadgeOptions contains options for badge request.
type RequestBadgeOptions struct {
	AgentID    string
	Domain     string
	TTL        time.Duration
	TrustLevel string
	Audience   []string
}

// RequestBadgeResult contains the result of a badge request.
type RequestBadgeResult struct {
	Token      string
	JTI        string
	Subject    string
	TrustLevel string
	ExpiresAt  time.Time
}

// RequestBadge requests a new badge from the CA.
func (c *Client) RequestBadge(ctx context.Context, opts RequestBadgeOptions) (*RequestBadgeResult, error) {
	if opts.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}

	// Build request body
	reqBody := map[string]interface{}{}
	
	if opts.Domain != "" {
		reqBody["domain"] = opts.Domain
	}
	
	if opts.TrustLevel != "" {
		reqBody["trustLevel"] = opts.TrustLevel
	}
	
	if opts.TTL > 0 {
		reqBody["duration"] = opts.TTL.String()
	}
	
	if len(opts.Audience) > 0 {
		reqBody["audience"] = opts.Audience
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/v1/agents/%s/badge", c.CAURL, opts.AgentID)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "capiscio-core/1.0")

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

	// Handle error responses
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, &ClientError{
			Code:    "AUTH_INVALID",
			Message: "invalid or expired API key",
		}
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, &ClientError{
			Code:    "FORBIDDEN",
			Message: "agent is disabled or you don't have permission",
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &ClientError{
			Code:    "AGENT_NOT_FOUND",
			Message: fmt.Sprintf("agent not found: %s", opts.AgentID),
		}
	}

	if resp.StatusCode == http.StatusConflict {
		// Agent has no domain configured
		var errResp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
			return nil, &ClientError{
				Code:    "DOMAIN_REQUIRED",
				Message: errResp.Error,
			}
		}
		return nil, &ClientError{
			Code:    "CONFLICT",
			Message: "agent configuration conflict",
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &ClientError{
			Code:    "CA_ERROR",
			Message: fmt.Sprintf("CA returned status %d: %s", resp.StatusCode, string(respBody)),
		}
	}

	// Parse success response
	var caResp struct {
		Success bool `json:"success"`
		Data    struct {
			Token      string    `json:"token"`
			JTI        string    `json:"jti"`
			Subject    string    `json:"subject"`
			TrustLevel string    `json:"trustLevel"`
			ExpiresAt  time.Time `json:"expiresAt"`
		} `json:"data"`
		Error string `json:"error"`
	}

	if err := json.Unmarshal(respBody, &caResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if !caResp.Success {
		return nil, &ClientError{
			Code:    "CA_ERROR",
			Message: caResp.Error,
		}
	}

	return &RequestBadgeResult{
		Token:      caResp.Data.Token,
		JTI:        caResp.Data.JTI,
		Subject:    caResp.Data.Subject,
		TrustLevel: caResp.Data.TrustLevel,
		ExpiresAt:  caResp.Data.ExpiresAt,
	}, nil
}

// ClientError represents an error from the badge client.
type ClientError struct {
	Code    string
	Message string
}

func (e *ClientError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// IsAuthError returns true if this is an authentication error.
func (e *ClientError) IsAuthError() bool {
	return e.Code == "AUTH_INVALID" || e.Code == "FORBIDDEN"
}

// IsNotFoundError returns true if the agent was not found.
func (e *ClientError) IsNotFoundError() bool {
	return e.Code == "AGENT_NOT_FOUND"
}

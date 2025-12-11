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

// buildRequestBody constructs the request body map from options.
func (c *Client) buildRequestBody(opts RequestBadgeOptions) ([]byte, error) {
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

	return json.Marshal(reqBody)
}

// createBadgeRequest creates an HTTP request for badge issuance.
func (c *Client) createBadgeRequest(ctx context.Context, agentID string, body []byte) (*http.Request, error) {
	url := fmt.Sprintf("%s/v1/agents/%s/badge", c.CAURL, agentID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("User-Agent", "capiscio-core/1.0")

	return req, nil
}

// handleErrorResponse converts HTTP error status codes to ClientError.
func (c *Client) handleErrorResponse(statusCode int, respBody []byte, agentID string) error {
	switch statusCode {
	case http.StatusUnauthorized:
		return &ClientError{Code: "AUTH_INVALID", Message: "invalid or expired API key"}
	case http.StatusForbidden:
		return &ClientError{Code: "FORBIDDEN", Message: "agent is disabled or you don't have permission"}
	case http.StatusNotFound:
		return &ClientError{Code: "AGENT_NOT_FOUND", Message: fmt.Sprintf("agent not found: %s", agentID)}
	case http.StatusConflict:
		return c.parseConflictError(respBody)
	default:
		return &ClientError{Code: "CA_ERROR", Message: fmt.Sprintf("CA returned status %d: %s", statusCode, string(respBody))}
	}
}

// parseConflictError parses conflict error responses.
func (c *Client) parseConflictError(respBody []byte) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error != "" {
		return &ClientError{Code: "DOMAIN_REQUIRED", Message: errResp.Error}
	}
	return &ClientError{Code: "CONFLICT", Message: "agent configuration conflict"}
}

// parseSuccessResponse parses a successful badge response.
func (c *Client) parseSuccessResponse(respBody []byte) (*RequestBadgeResult, error) {
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
		return nil, &ClientError{Code: "CA_ERROR", Message: caResp.Error}
	}

	return &RequestBadgeResult{
		Token:      caResp.Data.Token,
		JTI:        caResp.Data.JTI,
		Subject:    caResp.Data.Subject,
		TrustLevel: caResp.Data.TrustLevel,
		ExpiresAt:  caResp.Data.ExpiresAt,
	}, nil
}

// RequestBadge requests a new badge from the CA.
func (c *Client) RequestBadge(ctx context.Context, opts RequestBadgeOptions) (*RequestBadgeResult, error) {
	if opts.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}

	// Build request body
	bodyBytes, err := c.buildRequestBody(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	req, err := c.createBadgeRequest(ctx, opts.AgentID, bodyBytes)
	if err != nil {
		return nil, err
	}

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
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.StatusCode, respBody, opts.AgentID)
	}

	return c.parseSuccessResponse(respBody)
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

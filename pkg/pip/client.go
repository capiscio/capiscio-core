package pip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PDPClient is the engine-agnostic interface for policy decisions.
// Implementations exist for OPA, Cedar, and any HTTP-based PDP.
type PDPClient interface {
	// Evaluate sends a PIP decision request and returns the response.
	// Implementations MUST set a reasonable timeout (RECOMMENDED: 500ms).
	// On error (network, timeout, malformed response), return error — do NOT
	// return a synthetic ALLOW or DENY. The PEP handles PDP unavailability
	// per enforcement mode (§7.4).
	Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error)
}

// TODO(governance-workbench): PDPManager interface — policy push/pull path.
// The governance workbench (planned post-PyCon) will need a management interface
// for pushing/syncing policy to external PDPs. That interface must be designed
// with knowledge of how each target PDP handles policy updates:
//   - OPA: pull-based bundles (not push), bundle server API
//   - Cedar: entity-based policy stores with schemas
//   - AWS Verified Permissions: versioned policy stores
//
// Define PDPManager when there is one real design partner, one target PDP engine,
// and actual workbench requirements. Not before.

// DefaultPDPTimeout is the recommended PDP query timeout.
const DefaultPDPTimeout = 500 * time.Millisecond

// HTTPPDPClient is the reference implementation of PDPClient for any REST-based PDP.
type HTTPPDPClient struct {
	endpoint string
	client   *http.Client
	pepID    string
}

// HTTPPDPClientOption configures an HTTPPDPClient.
type HTTPPDPClientOption func(*HTTPPDPClient)

// WithPEPID sets the PEP identifier included in requests.
func WithPEPID(id string) HTTPPDPClientOption {
	return func(c *HTTPPDPClient) {
		c.pepID = id
	}
}

// WithHTTPClient sets a custom HTTP client (e.g., for custom TLS or timeouts).
func WithHTTPClient(hc *http.Client) HTTPPDPClientOption {
	return func(c *HTTPPDPClient) {
		c.client = hc
	}
}

// NewHTTPPDPClient creates an HTTP-based PDP client.
// endpoint is the PDP evaluation URL.
// timeout controls the HTTP client timeout (use DefaultPDPTimeout if unsure).
func NewHTTPPDPClient(endpoint string, timeout time.Duration, opts ...HTTPPDPClientOption) *HTTPPDPClient {
	c := &HTTPPDPClient{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: timeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Evaluate sends a PIP decision request to the HTTP PDP and returns the response.
func (c *HTTPPDPClient) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("pip: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pip: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.pepID != "" {
		httpReq.Header.Set("X-Capiscio-PEP-ID", c.pepID)
	}

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("pip: pdp request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, fmt.Errorf("pip: read pdp response: %w", err)
	}

	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("pip: pdp returned status %d", httpResp.StatusCode)
	}

	var resp DecisionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("pip: unmarshal pdp response: %w", err)
	}

	// Validate response per RFC-005 §6.1
	if !ValidDecision(resp.Decision) {
		return nil, fmt.Errorf("pip: pdp returned invalid decision %q (expected ALLOW or DENY)", resp.Decision)
	}
	if resp.DecisionID == "" {
		return nil, fmt.Errorf("pip: pdp returned empty decision_id (non-compliant)")
	}

	return &resp, nil
}

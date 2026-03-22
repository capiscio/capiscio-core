// Package pdp implements the Policy Decision Point for local policy evaluation.
// It provides bundle fetching, OPA-based evaluation, and background refresh management.
package pdp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// BundleContents holds the compiled policy bundle from the capiscio-server.
// This mirrors the server's bundle format to allow in-process OPA evaluation.
type BundleContents struct {
	Modules  map[string]string      `json:"modules"`            // filename → Rego source
	Data     map[string]interface{} `json:"data"`               // OPA data document
	Revision string                 `json:"revision,omitempty"` // content-addressable revision hash
}

// BundleClient pulls OPA policy bundles from the capiscio-server bundle endpoint.
type BundleClient struct {
	bundleURL string
	apiKey    string
	client    *http.Client
	logger    *slog.Logger
}

// BundleClientOption configures a BundleClient.
type BundleClientOption func(*BundleClient)

// WithBundleHTTPClient sets a custom HTTP client for the bundle client.
// A nil value is ignored.
func WithBundleHTTPClient(c *http.Client) BundleClientOption {
	return func(bc *BundleClient) {
		if c != nil {
			bc.client = c
		}
	}
}

// WithBundleLogger sets the logger for the bundle client.
// A nil value is ignored.
func WithBundleLogger(l *slog.Logger) BundleClientOption {
	return func(bc *BundleClient) {
		if l != nil {
			bc.logger = l
		}
	}
}

// NewBundleClient creates a new bundle pull client.
// The bundleURL should include the full path, e.g. "https://api.capisc.io/v1/bundles/{workspace_id}".
// The apiKey is sent as X-Capiscio-Registry-Key header.
func NewBundleClient(bundleURL, apiKey string, opts ...BundleClientOption) (*BundleClient, error) {
	if bundleURL == "" {
		return nil, fmt.Errorf("pdp: bundle URL is required")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("pdp: API key is required for bundle authentication")
	}

	bc := &BundleClient{
		bundleURL: bundleURL,
		apiKey:    apiKey,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(bc)
	}
	return bc, nil
}

// Fetch pulls the current bundle from the server.
// Returns the parsed bundle contents or an error if the fetch fails.
// A nil bundle with a nil error is NOT a valid return — always returns one or the other.
func (bc *BundleClient) Fetch(ctx context.Context) (*BundleContents, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bc.bundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("pdp: create bundle request: %w", err)
	}
	req.Header.Set("X-Capiscio-Registry-Key", bc.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := bc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pdp: bundle fetch failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, fmt.Errorf("pdp: bundle not yet available (503)")
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("pdp: bundle authentication failed (%d) — check CAPISCIO_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("pdp: bundle fetch returned %d: %s", resp.StatusCode, string(body))
	}

	var bundle BundleContents
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("pdp: decode bundle response: %w", err)
	}

	if len(bundle.Modules) == 0 {
		return nil, fmt.Errorf("pdp: bundle contains no Rego modules")
	}

	bc.logger.Info("bundle fetched",
		slog.String("revision", bundle.Revision),
		slog.Int("modules", len(bundle.Modules)),
	)

	return &bundle, nil
}

// BundleURL returns the configured bundle endpoint URL.
func (bc *BundleClient) BundleURL() string {
	return bc.bundleURL
}

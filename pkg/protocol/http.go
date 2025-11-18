package protocol

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// HTTPClient implements the Client interface for HTTP+JSON transport.
type HTTPClient struct {
	url    string
	client *http.Client
}

// NewHTTPClient creates a new HTTPClient.
func NewHTTPClient(url string) *HTTPClient {
	return &HTTPClient{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Ping performs a simple GET request to the agent URL to check availability.
func (c *HTTPClient) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// We consider 5xx errors as failure. 404 might mean the endpoint exists but resource doesn't,
	// which implies the server is up. However, for an agent endpoint, 404 usually means bad config.
	// Let's be strict: 200-299 is success.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return time.Since(start), nil
}

func (c *HTTPClient) Close() error {
	return nil
}

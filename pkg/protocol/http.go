package protocol

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
// It attempts to call 'GET /tasks' which is a standard v0.3.0 endpoint.
func (c *HTTPClient) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()

	// Construct the URL for tasks/list
	targetURL := c.url
	if !strings.HasSuffix(targetURL, "/") {
		targetURL += "/"
	}
	targetURL += "tasks?limit=1"

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// We consider 5xx errors as failure.
	// 401/403 is actually a success for liveness (server is there, just protected).
	// 200-299 is success.
	if resp.StatusCode >= 500 {
		return 0, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	return time.Since(start), nil
}

func (c *HTTPClient) Close() error {
	return nil
}

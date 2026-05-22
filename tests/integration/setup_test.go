package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	// apiBaseURL is the base URL for the capiscio-server
	apiBaseURL string

	// serverAvailable is true when the live server is reachable.
	// Tests that require it should call requireServer(t).
	serverAvailable bool
)

// requireServer skips a test if the live capiscio-server is not running.
func requireServer(t *testing.T) {
	t.Helper()
	if !serverAvailable {
		t.Skip("Skipping: live capiscio-server not available at " + apiBaseURL)
	}
}

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	// Get API URL from environment
	apiBaseURL = os.Getenv("API_BASE_URL")
	if apiBaseURL == "" {
		apiBaseURL = "http://localhost:8080"
	}

	// Check if server is available (don't block on it)
	if err := waitForServer(apiBaseURL, 30*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Server not ready: %v (server-dependent tests will be skipped)\n", err)
		serverAvailable = false
	} else {
		serverAvailable = true
	}

	os.Exit(m.Run())
}

// waitForServer waits for the server to be healthy
func waitForServer(baseURL string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	healthURL := fmt.Sprintf("%s/health", baseURL)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for server at %s", baseURL)
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
			if err != nil {
				continue
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				fmt.Printf("Server is ready at %s\n", baseURL)
				return nil
			}
		}
	}
}

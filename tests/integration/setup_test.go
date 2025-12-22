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
	// API_BASE_URL is the base URL for the capiscio-server
	API_BASE_URL string
)

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	// Get API URL from environment
	API_BASE_URL = os.Getenv("API_BASE_URL")
	if API_BASE_URL == "" {
		API_BASE_URL = "http://localhost:8080"
	}

	// Wait for server to be ready
	if err := waitForServer(API_BASE_URL, 30*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Server not ready: %v\n", err)
		os.Exit(1)
	}

	// Run tests
	code := m.Run()
	os.Exit(code)
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

package protocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPClient_Ping_Success(t *testing.T) {
	// Start a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path and query
		assert.Equal(t, "/tasks", r.URL.Path)
		assert.Equal(t, "1", r.URL.Query().Get("limit"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)
	defer client.Close()

	latency, err := client.Ping(context.Background())
	assert.NoError(t, err)
	assert.True(t, latency > 0)
}

func TestHTTPClient_Ping_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)
	defer client.Close()

	_, err := client.Ping(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server returned status: 500")
}

func TestHTTPClient_Ping_NetworkError(t *testing.T) {
	// Create a client pointing to a closed port
	client := NewHTTPClient("http://127.0.0.1:0")
	defer client.Close()

	_, err := client.Ping(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestHTTPClient_Ping_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)
	// Override client timeout for test
	client.client.Timeout = 10 * time.Millisecond
	defer client.Close()

	_, err := client.Ping(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded") // or "Client.Timeout exceeded" depending on Go version/impl
}

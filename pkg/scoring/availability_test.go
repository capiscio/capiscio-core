package scoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/pkg/agentcard"
	"github.com/stretchr/testify/assert"
)

func TestAvailabilityScorer_Score_JSONRPC_Success(t *testing.T) {
	// Mock server that responds to JSON-RPC
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate processing time
		time.Sleep(10 * time.Millisecond)

		// Simple valid response
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc": "2.0", "result": ["skill1"], "id": 1}`))
	}))
	defer server.Close()

	scorer := NewAvailabilityScorer(0)
	card := &agentcard.AgentCard{
		URL:                server.URL,
		PreferredTransport: agentcard.TransportJSONRPC,
	}

	res := scorer.Score(context.Background(), card)

	assert.True(t, res.Tested)
	assert.Equal(t, server.URL, res.EndpointURL)
	assert.Empty(t, res.Error)
	assert.Equal(t, 100.0, res.Score) // < 200ms
	assert.True(t, res.LatencyMS > 0)
}

func TestAvailabilityScorer_Score_HTTP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	scorer := NewAvailabilityScorer(0)
	card := &agentcard.AgentCard{
		URL:                server.URL,
		PreferredTransport: agentcard.TransportHTTPJSON,
	}

	res := scorer.Score(context.Background(), card)

	assert.True(t, res.Tested)
	assert.Equal(t, 100.0, res.Score)
	assert.Empty(t, res.Error)
}

func TestAvailabilityScorer_Score_Latency_Tiers(t *testing.T) {
	tests := []struct {
		name          string
		latency       time.Duration
		expectedScore float64
	}{
		{"Fast", 50 * time.Millisecond, 100.0},
		{"Medium", 300 * time.Millisecond, 90.0},
		{"Slow", 600 * time.Millisecond, 70.0},
		{"VerySlow", 1100 * time.Millisecond, 50.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(tt.latency)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			scorer := NewAvailabilityScorer(0)
			card := &agentcard.AgentCard{
				URL:                server.URL,
				PreferredTransport: agentcard.TransportHTTPJSON,
			}

			res := scorer.Score(context.Background(), card)
			assert.Equal(t, tt.expectedScore, res.Score)
		})
	}
}

func TestAvailabilityScorer_Score_ConnectionError(t *testing.T) {
	scorer := NewAvailabilityScorer(0)
	card := &agentcard.AgentCard{
		URL:                "http://127.0.0.1:0", // Invalid port
		PreferredTransport: agentcard.TransportHTTPJSON,
	}

	res := scorer.Score(context.Background(), card)

	assert.True(t, res.Tested)
	assert.Equal(t, 0.0, res.Score)
	assert.NotEmpty(t, res.Error)
}

func TestAvailabilityScorer_Score_UnsupportedTransport(t *testing.T) {
	scorer := NewAvailabilityScorer(0)
	card := &agentcard.AgentCard{
		URL:                "http://example.com",
		PreferredTransport: "ftp",
	}

	res := scorer.Score(context.Background(), card)

	assert.True(t, res.Tested)
	assert.Equal(t, 0.0, res.Score)
	assert.Contains(t, res.Error, "Unsupported transport")
}

func TestAvailabilityScorer_Score_GRPC_NotSupported(t *testing.T) {
	scorer := NewAvailabilityScorer(0)
	card := &agentcard.AgentCard{
		URL:                "http://example.com",
		PreferredTransport: agentcard.TransportGRPC,
	}

	res := scorer.Score(context.Background(), card)

	assert.True(t, res.Tested)
	assert.Equal(t, 0.0, res.Score)
	assert.Contains(t, res.Error, "GRPC transport not yet supported")
}

func TestAvailabilityScorer_Score_DefaultTransport(t *testing.T) {
	// Should default to JSONRPC
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc": "2.0", "result": [], "id": 1}`))
	}))
	defer server.Close()

	scorer := NewAvailabilityScorer(0)
	card := &agentcard.AgentCard{
		URL:                server.URL,
		PreferredTransport: "", // Empty
	}

	res := scorer.Score(context.Background(), card)

	assert.True(t, res.Tested)
	assert.Equal(t, 100.0, res.Score)
	assert.Empty(t, res.Error)
}

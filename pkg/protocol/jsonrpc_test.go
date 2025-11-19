package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSONRPCClient_Ping_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		var req jsonRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		assert.Equal(t, "2.0", req.JSONRPC)
		assert.Equal(t, "tasks/list", req.Method)
		
		// Verify params
		params, ok := req.Params.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, float64(1), params["limit"]) // JSON unmarshals numbers as float64

		// Send response
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			Result:  []string{"task1"},
			ID:      req.ID,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewJSONRPCClient(server.URL)
	defer client.Close()

	latency, err := client.Ping(context.Background())
	assert.NoError(t, err)
	assert.True(t, latency > 0)
}

func TestJSONRPCClient_Ping_MethodNotFound(t *testing.T) {
	// Even if the method is not found, the agent is "available" because it speaks JSON-RPC
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			Error: &jsonRPCError{
				Code:    -32601,
				Message: "Method not found",
			},
			ID: 1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewJSONRPCClient(server.URL)
	defer client.Close()

	latency, err := client.Ping(context.Background())
	assert.NoError(t, err)
	assert.True(t, latency > 0)
}

func TestJSONRPCClient_Ping_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewJSONRPCClient(server.URL)
	defer client.Close()

	_, err := client.Ping(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON-RPC response")
}

func TestJSONRPCClient_Ping_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewJSONRPCClient(server.URL)
	defer client.Close()

	_, err := client.Ping(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server returned status: 500")
}

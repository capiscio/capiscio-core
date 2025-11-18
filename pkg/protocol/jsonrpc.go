package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// JSONRPCClient implements the Client interface for JSON-RPC transport over HTTP.
type JSONRPCClient struct {
	url    string
	client *http.Client
}

// NewJSONRPCClient creates a new JSONRPCClient.
func NewJSONRPCClient(url string) *JSONRPCClient {
	return &JSONRPCClient{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Ping sends a standard JSON-RPC request to check availability.
// It attempts to call 'agent.listSkills' which is a common read-only method.
// Even if the method is not found, a valid JSON-RPC error response indicates the agent is alive.
func (c *JSONRPCClient) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()

	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "agent.listSkills",
		ID:      1,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	var rpcResp jsonRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return 0, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}

	// We don't check rpcResp.Error because getting an error (e.g. MethodNotFound)
	// still means the JSON-RPC server is up and speaking the protocol.

	return time.Since(start), nil
}

func (c *JSONRPCClient) Close() error {
	return nil
}

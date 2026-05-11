//go:build !opa_no_wasm

package rpc

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMCPServiceWithConfig_BadgeOnlyMode(t *testing.T) {
	// No PDP env vars set → badge-only mode (PDPClient is nil)
	os.Unsetenv("CAPISCIO_BUNDLE_URL")
	os.Unsetenv("CAPISCIO_API_KEY")

	cfg := MCPServiceConfig{}

	svc, err := NewMCPServiceWithConfig(cfg)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewMCPServiceWithConfig_EnforcementModeFromEnv(t *testing.T) {
	os.Unsetenv("CAPISCIO_BUNDLE_URL")
	t.Setenv("CAPISCIO_ENFORCEMENT_MODE", "enforce")

	cfg := MCPServiceConfig{}

	svc, err := NewMCPServiceWithConfig(cfg)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewMCPServiceWithConfig_PDPClientWired(t *testing.T) {
	// Inject a mock initPDPFunc that returns a real PDPClient.
	mockClient := &mockPDPClient{}
	orig := initPDPFunc
	initPDPFunc = func(_ context.Context) (pip.PDPClient, error) {
		return mockClient, nil
	}
	t.Cleanup(func() { initPDPFunc = orig })

	cfg := MCPServiceConfig{}
	svc, err := NewMCPServiceWithConfig(cfg)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewMCPServiceWithConfig_PDPInitError(t *testing.T) {
	// initPDPFunc returns error → NewMCPServiceWithConfig propagates it.
	orig := initPDPFunc
	initPDPFunc = func(_ context.Context) (pip.PDPClient, error) {
		return nil, errors.New("bundle auth failed")
	}
	t.Cleanup(func() { initPDPFunc = orig })

	cfg := MCPServiceConfig{}
	svc, err := NewMCPServiceWithConfig(cfg)
	assert.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "bundle auth failed")
}

func TestNewMCPService_FallbackOnError(t *testing.T) {
	// When initPDPFunc errors, NewMCPService falls back to badge-only mode.
	orig := initPDPFunc
	callCount := 0
	initPDPFunc = func(_ context.Context) (pip.PDPClient, error) {
		callCount++
		if callCount == 1 {
			return nil, errors.New("first call fails")
		}
		return nil, nil // second call succeeds (badge-only)
	}
	t.Cleanup(func() { initPDPFunc = orig })

	os.Unsetenv("CAPISCIO_TRUST_STORE_KEY")
	svc := NewMCPService()
	assert.NotNil(t, svc, "NewMCPService must never return nil")
	assert.Equal(t, 2, callCount, "should retry after first failure")
}

// mockPDPClient satisfies pip.PDPClient for testing.
type mockPDPClient struct{}

func (m *mockPDPClient) Evaluate(_ context.Context, _ *pip.DecisionRequest) (*pip.DecisionResponse, error) {
	return &pip.DecisionResponse{Decision: pip.DecisionAllow}, nil
}

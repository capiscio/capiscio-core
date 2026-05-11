//go:build !opa_no_wasm

package rpc

import (
	"os"
	"testing"

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
	// Without OPA tag, initLocalPDP is a no-op, but enforcement mode
	// is still read from env and plumbed through.
	os.Unsetenv("CAPISCIO_BUNDLE_URL")
	t.Setenv("CAPISCIO_ENFORCEMENT_MODE", "enforce")

	cfg := MCPServiceConfig{}

	svc, err := NewMCPServiceWithConfig(cfg)
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewMCPService_FallbackOnError(t *testing.T) {
	// NewMCPService should not panic even if config is bad —
	// it should fall back to badge-only mode.
	os.Unsetenv("CAPISCIO_BUNDLE_URL")
	os.Unsetenv("CAPISCIO_TRUST_STORE_KEY")

	svc := NewMCPService()
	assert.NotNil(t, svc, "NewMCPService must never return nil")
}

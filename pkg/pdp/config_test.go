//go:build opa_no_wasm

package pdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalPDP_DisabledWithEmptyURL(t *testing.T) {
	cfg := PolicyEnforcementConfig{}
	pdp, err := NewLocalPDP(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, pdp)
}

func TestNewLocalPDP_ErrorOnMissingAPIKey(t *testing.T) {
	cfg := PolicyEnforcementConfig{
		BundleURL: "http://example.com/v1/bundles/ws1",
	}
	_, err := NewLocalPDP(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CAPISCIO_API_KEY")
}

func TestNewLocalPDP_SuccessfulInit(t *testing.T) {
	bundle := BundleContents{
		Modules:  map[string]string{"policy.rego": regoAlwaysAllow},
		Revision: "rev-init",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	cfg := PolicyEnforcementConfig{
		BundleURL:       srv.URL + "/v1/bundles/ws1",
		APIKey:          "test-key",
		PollInterval:    1 * time.Second,
		MaxAge:          5 * time.Minute,
		EnforcementMode: pip.EMObserve,
	}

	pdp, err := NewLocalPDP(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, pdp)
	defer pdp.Stop()

	// Should have loaded the bundle
	assert.True(t, pdp.Client.HasBundle())

	// Should be able to evaluate
	resp, err := pdp.Client.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
}

func TestNewLocalPDP_ObserveModeContinuesOnFetchFailure(t *testing.T) {
	// Server returns 503,
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := PolicyEnforcementConfig{
		BundleURL:       srv.URL + "/v1/bundles/ws1",
		APIKey:          "test-key",
		PollInterval:    100 * time.Millisecond,
		EnforcementMode: pip.EMObserve,
	}

	pdp, err := NewLocalPDP(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, pdp, "EM-OBSERVE should not fail on initial fetch error")
	defer pdp.Stop()

	// No bundle loaded yet
	assert.False(t, pdp.Client.HasBundle())
}

func TestNewLocalPDP_StrictModeFailsOnFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := PolicyEnforcementConfig{
		BundleURL:       srv.URL + "/v1/bundles/ws1",
		APIKey:          "test-key",
		EnforcementMode: pip.EMStrict,
	}

	_, err := NewLocalPDP(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EM-STRICT")
}

func TestNewLocalPDP_GuardModeContinuesOnFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := PolicyEnforcementConfig{
		BundleURL:       srv.URL + "/v1/bundles/ws1",
		APIKey:          "test-key",
		PollInterval:    100 * time.Millisecond,
		EnforcementMode: pip.EMGuard,
	}

	pdp, err := NewLocalPDP(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, pdp, "EM-GUARD should not fail on initial fetch error")
	defer pdp.Stop()
}

func TestNewLocalPDP_StopIdempotent(t *testing.T) {
	bundle := BundleContents{
		Modules:  map[string]string{"policy.rego": regoAlwaysAllow},
		Revision: "rev-1",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	cfg := PolicyEnforcementConfig{
		BundleURL: srv.URL + "/v1/bundles/ws1",
		APIKey:    "test-key",
	}

	pdp, err := NewLocalPDP(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, pdp)

	pdp.Stop()
	pdp.Stop() // idempotent
}

func TestConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv("CAPISCIO_BUNDLE_URL", "")
	t.Setenv("CAPISCIO_API_KEY", "")
	t.Setenv("CAPISCIO_BUNDLE_POLL_INTERVAL", "")
	t.Setenv("CAPISCIO_BUNDLE_MAX_AGE", "")
	t.Setenv("CAPISCIO_ENFORCEMENT_MODE", "")

	cfg, err := ConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.BundleURL)
	assert.Equal(t, "", cfg.APIKey)
	assert.Equal(t, time.Duration(0), cfg.PollInterval) // 0 means use default
	assert.Equal(t, time.Duration(0), cfg.MaxAge)
	assert.Equal(t, pip.EMObserve, cfg.EnforcementMode)
}

func TestConfigFromEnv_AllSet(t *testing.T) {
	t.Setenv("CAPISCIO_BUNDLE_URL", "http://server:8080/v1/bundles/ws1")
	t.Setenv("CAPISCIO_API_KEY", "my-key")
	t.Setenv("CAPISCIO_BUNDLE_POLL_INTERVAL", "45s")
	t.Setenv("CAPISCIO_BUNDLE_MAX_AGE", "15m")
	t.Setenv("CAPISCIO_ENFORCEMENT_MODE", "guard")

	cfg, err := ConfigFromEnv()
	require.NoError(t, err)
	assert.Equal(t, "http://server:8080/v1/bundles/ws1", cfg.BundleURL)
	assert.Equal(t, "my-key", cfg.APIKey)
	assert.Equal(t, 45*time.Second, cfg.PollInterval)
	assert.Equal(t, 15*time.Minute, cfg.MaxAge)
	assert.Equal(t, pip.EMGuard, cfg.EnforcementMode)
}

func TestConfigFromEnv_InvalidPollInterval(t *testing.T) {
	t.Setenv("CAPISCIO_BUNDLE_URL", "http://server:8080/v1/bundles/ws1")
	t.Setenv("CAPISCIO_BUNDLE_POLL_INTERVAL", "not-a-duration")

	_, err := ConfigFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CAPISCIO_BUNDLE_POLL_INTERVAL")
}

func TestConfigFromEnv_InvalidMaxAge(t *testing.T) {
	t.Setenv("CAPISCIO_BUNDLE_URL", "http://server:8080/v1/bundles/ws1")
	t.Setenv("CAPISCIO_BUNDLE_MAX_AGE", "invalid")

	_, err := ConfigFromEnv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CAPISCIO_BUNDLE_MAX_AGE")
}

func TestNewLocalPDP_CustomOptionsPassthrough(t *testing.T) {
	bundle := BundleContents{
		Modules:  map[string]string{"policy.rego": regoAlwaysAllow},
		Revision: "rev-1",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	cfg := PolicyEnforcementConfig{
		BundleURL: srv.URL + "/v1/bundles/ws1",
		APIKey:    "test-key",
	}

	// Pass custom options that override defaults
	pdp, err := NewLocalPDP(context.Background(), cfg,
		WithPollInterval(5*time.Second),
		WithMaxAge(2*time.Minute),
	)
	require.NoError(t, err)
	require.NotNil(t, pdp)
	defer pdp.Stop()

	assert.Equal(t, 5*time.Second, pdp.Manager.pollInterval)
	assert.Equal(t, 2*time.Minute, pdp.Manager.maxAge)
}

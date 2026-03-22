//go:build opa_no_wasm

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pdp"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Data plane E2E tests exercise the full agent-side policy enforcement stack
// (BundleClient → OPALocalClient → BundleManager) against a live capiscio-server.
//
// Prerequisites:
//   - Running capiscio-server with embedded PDP (API_BASE_URL env var)
//   - Test API key with bundle:read permission (TEST_API_KEY env var)
//   - Test workspace/org (TEST_ORG_ID env var)

func testAPIKey() string {
	k := os.Getenv("TEST_API_KEY")
	if k == "" {
		return "test_api_key_e2e"
	}
	return k
}

func testOrgID() string {
	id := os.Getenv("TEST_ORG_ID")
	if id == "" {
		return "22222222-2222-2222-2222-222222222222"
	}
	return id
}

func bundleURL() string {
	return fmt.Sprintf("%s/v1/bundles/%s", apiBaseURL, testOrgID())
}

// TestDataPlane_BundleClientFetch verifies the BundleClient can pull a real
// bundle from the server and the response contains valid Rego modules.
func TestDataPlane_BundleClientFetch(t *testing.T) {
	client, err := pdp.NewBundleClient(bundleURL(), testAPIKey())
	require.NoError(t, err)

	bundle, err := client.Fetch(context.Background())
	require.NoError(t, err, "bundle fetch from live server should succeed")

	assert.NotEmpty(t, bundle.Modules, "bundle should contain at least one Rego module")
	assert.NotEmpty(t, bundle.Revision, "bundle should have a revision")

	// Verify modules are parseable Rego (contain "package" keyword)
	for name, src := range bundle.Modules {
		assert.Contains(t, src, "package", "module %q should be valid Rego", name)
	}
}

// TestDataPlane_OPALocalClientEvaluatesBundle verifies that a bundle fetched
// from the live server can be loaded and evaluated by OPALocalClient.
func TestDataPlane_OPALocalClientEvaluatesBundle(t *testing.T) {
	client, err := pdp.NewBundleClient(bundleURL(), testAPIKey())
	require.NoError(t, err)

	bundle, err := client.Fetch(context.Background())
	require.NoError(t, err)

	evaluator := pdp.NewOPALocalClient()
	err = evaluator.LoadBundle(context.Background(), bundle.Modules, bundle.Data)
	require.NoError(t, err, "loading real server bundle into OPA should succeed")

	assert.True(t, evaluator.HasBundle())
	assert.Greater(t, evaluator.BundleAge(), time.Duration(0))

	// Evaluate a basic request — the starter policy should produce a decision
	req := &pip.DecisionRequest{
		PIPVersion: "1.0",
		Subject: pip.SubjectAttributes{
			DID:        "did:web:example.agent",
			TrustLevel: 1,
		},
		Action: pip.ActionAttributes{
			Operation: "message/send",
		},
		Resource: pip.ResourceAttributes{
			Identifier: "test-resource",
		},
		Context: pip.ContextAttributes{
			EnforcementMode: pip.EMObserve,
		},
	}

	resp, err := evaluator.Evaluate(context.Background(), req)
	require.NoError(t, err, "evaluate with server bundle should not error")
	assert.NotEmpty(t, resp.Decision, "should produce a decision")
	assert.NotEmpty(t, resp.DecisionID, "should have a decision ID")
}

// TestDataPlane_NewLocalPDPFullStack verifies the one-call NewLocalPDP
// initialization against a live server.
func TestDataPlane_NewLocalPDPFullStack(t *testing.T) {
	cfg := pdp.PolicyEnforcementConfig{
		BundleURL:       bundleURL(),
		APIKey:          testAPIKey(),
		PollInterval:    5 * time.Second,
		MaxAge:          2 * time.Minute,
		EnforcementMode: pip.EMObserve,
	}

	localPDP, err := pdp.NewLocalPDP(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, localPDP)
	defer localPDP.Stop()

	assert.True(t, localPDP.Client.HasBundle(), "initial bundle should be loaded")
	assert.False(t, localPDP.Manager.IsStale(), "fresh bundle should not be stale")

	// Evaluate
	req := &pip.DecisionRequest{
		PIPVersion: "1.0",
		Subject: pip.SubjectAttributes{
			DID:        "did:web:test-agent.example.com",
			TrustLevel: 2,
		},
		Action: pip.ActionAttributes{
			Operation: "message/send",
		},
		Resource: pip.ResourceAttributes{
			Identifier: "e2e-test",
		},
		Context: pip.ContextAttributes{
			EnforcementMode: pip.EMObserve,
		},
	}

	resp, err := localPDP.Client.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Decision)
}

// TestDataPlane_BundleRevisionConsistency verifies that consecutive fetches
// return the same revision when no config has changed.
func TestDataPlane_BundleRevisionConsistency(t *testing.T) {
	client, err := pdp.NewBundleClient(bundleURL(), testAPIKey())
	require.NoError(t, err)

	bundle1, err := client.Fetch(context.Background())
	require.NoError(t, err)

	bundle2, err := client.Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, bundle1.Revision, bundle2.Revision,
		"consecutive fetches without config changes should return same revision")
}

// TestDataPlane_BundleAuthRejection verifies that an invalid API key
// is properly rejected by the server.
func TestDataPlane_BundleAuthRejection(t *testing.T) {
	client, err := pdp.NewBundleClient(bundleURL(), "invalid-key-that-should-fail")
	require.NoError(t, err)

	_, err = client.Fetch(context.Background())
	require.Error(t, err, "invalid API key should be rejected")
	assert.Contains(t, err.Error(), "authentication failed")
}

// TestDataPlane_BundleContainsData verifies that the bundle data section
// contains expected agent/registry data from the server.
func TestDataPlane_BundleContainsData(t *testing.T) {
	client, err := pdp.NewBundleClient(bundleURL(), testAPIKey())
	require.NoError(t, err)

	bundle, err := client.Fetch(context.Background())
	require.NoError(t, err)

	// The server should include data (agents, config, etc.)
	if bundle.Data != nil {
		// Verify data is serializable (round-trip)
		encoded, err := json.Marshal(bundle.Data)
		require.NoError(t, err, "bundle data should be JSON-serializable")
		assert.Greater(t, len(encoded), 2, "bundle data should not be empty object")
	}
}

// TestDataPlane_BundleFetchHTTPHeaders verifies that the server respects
// standard HTTP semantics for the bundle endpoint.
func TestDataPlane_BundleFetchHTTPHeaders(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, bundleURL(), nil)
	require.NoError(t, err)
	req.Header.Set("X-Capiscio-Registry-Key", testAPIKey())

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")
}

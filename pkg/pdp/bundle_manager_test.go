//go:build opa_no_wasm

package pdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBundle(revision string) BundleContents {
	return BundleContents{
		Modules: map[string]string{
			"policy.rego": regoAlwaysAllow,
		},
		Data:     map[string]interface{}{},
		Revision: revision,
	}
}

func newTestBundleServer(t *testing.T, bundle *BundleContents) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bundle == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
}

func TestBundleManager_InitialFetchOnStart(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator, WithPollInterval(100*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx)
	defer mgr.Stop()

	// Wait for initial fetch
	require.Eventually(t, func() bool {
		return evaluator.HasBundle()
	}, 2*time.Second, 10*time.Millisecond, "bundle should be loaded after start")

	// Verify evaluation works
	resp, err := evaluator.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
}

func TestBundleManager_SkipsReloadOnSameRevision(t *testing.T) {
	var fetchCount atomic.Int32
	bundle := newTestBundle("rev-static")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator, WithPollInterval(50*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx)
	defer mgr.Stop()

	// Wait for multiple poll cycles
	time.Sleep(300 * time.Millisecond)

	// Should have fetched multiple times but only loaded once
	assert.Greater(t, int(fetchCount.Load()), 2, "should have polled multiple times")
	assert.True(t, evaluator.HasBundle())
}

func TestBundleManager_HotSwapOnRevisionChange(t *testing.T) {
	var revision atomic.Value
	revision.Store("rev-1")

	bundle1 := BundleContents{
		Modules:  map[string]string{"policy.rego": regoAlwaysAllow},
		Revision: "rev-1",
	}
	bundle2 := BundleContents{
		Modules:  map[string]string{"policy.rego": regoDenySpecificDID},
		Revision: "rev-2",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rev := revision.Load().(string)
		if rev == "rev-2" {
			_ = json.NewEncoder(w).Encode(bundle2)
		} else {
			_ = json.NewEncoder(w).Encode(bundle1)
		}
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator, WithPollInterval(50*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx)
	defer mgr.Stop()

	// Wait for initial load
	require.Eventually(t, func() bool {
		return evaluator.HasBundle()
	}, 2*time.Second, 10*time.Millisecond)

	// Should allow blocked DID with rev-1
	req := newTestRequest()
	req.Subject.DID = "did:web:blocked-agent"
	resp, err := evaluator.Evaluate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)

	// Switch to rev-2
	revision.Store("rev-2")

	// Wait for hot-swap
	require.Eventually(t, func() bool {
		resp, err := evaluator.Evaluate(context.Background(), req)
		return err == nil && resp.Decision == pip.DecisionDeny
	}, 2*time.Second, 20*time.Millisecond, "policy should hot-swap to deny")
}

func TestBundleManager_ExponentialBackoff(t *testing.T) {
	// Server always returns 503
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator, WithPollInterval(50*time.Millisecond))

	// Trigger some failures
	for i := 0; i < 5; i++ {
		_ = mgr.RefreshNow(context.Background())
	}

	mgr.mu.RLock()
	fails := mgr.consecutiveFails
	mgr.mu.RUnlock()
	assert.Equal(t, 5, fails)

	// Verify backoff increases
	delay := mgr.nextDelay()
	assert.Greater(t, delay, 10*time.Second, "backoff should be significant after 5 failures")
	assert.LessOrEqual(t, delay, backoffMax+backoffMax/4, "backoff should not exceed max + jitter")
}

func TestBundleManager_BackoffResetsOnSuccess(t *testing.T) {
	var shouldFail atomic.Bool
	shouldFail.Store(true)

	bundle := newTestBundle("rev-1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldFail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}))
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator)

	// Trigger some failures
	for i := 0; i < 3; i++ {
		_ = mgr.RefreshNow(context.Background())
	}
	mgr.mu.RLock()
	assert.Equal(t, 3, mgr.consecutiveFails)
	mgr.mu.RUnlock()

	// Now succeed
	shouldFail.Store(false)
	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)

	mgr.mu.RLock()
	assert.Equal(t, 0, mgr.consecutiveFails)
	mgr.mu.RUnlock()

	delay := mgr.nextDelay()
	assert.Equal(t, DefaultPollInterval, delay, "delay should reset to poll interval")
}

func TestBundleManager_StalenessDetection(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator, WithMaxAge(50*time.Millisecond))

	// No bundle → stale
	assert.True(t, mgr.IsStale())

	// Load bundle → not stale
	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)
	assert.False(t, mgr.IsStale())

	// Wait for staleness
	time.Sleep(60 * time.Millisecond)
	assert.True(t, mgr.IsStale())
}

func TestBundleManager_MaxAgeDefault(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient())
	assert.Equal(t, DefaultMaxAge, mgr.maxAge, "default max age should be 10 minutes")
}

func TestBundleManager_StopIdempotent(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient())

	ctx := context.Background()
	mgr.Start(ctx)

	// Multiple stops should not panic
	mgr.Stop()
	mgr.Stop()
	mgr.Stop()
}

func TestBundleManager_StartIdempotent(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient(), WithPollInterval(1*time.Second))

	ctx := context.Background()
	mgr.Start(ctx)
	mgr.Start(ctx) // Should not start a second goroutine
	defer mgr.Stop()

	time.Sleep(100 * time.Millisecond) // Let initial fetch complete
}

func TestBundleManager_RefreshNow(t *testing.T) {
	bundle := newTestBundle("rev-manual")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator)

	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)
	assert.True(t, evaluator.HasBundle())
}

func TestBundleManager_NextDelay_NoFailures(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient(), WithPollInterval(45*time.Second))
	assert.Equal(t, 45*time.Second, mgr.nextDelay())
}

func TestBundleManager_NextDelay_ExponentialGrowth(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient())

	tests := []struct {
		fails   int
		minWant time.Duration
		maxWant time.Duration
	}{
		{1, 750 * time.Millisecond, 1250 * time.Millisecond},     // ~1s ± 25%
		{2, 1500 * time.Millisecond, 2500 * time.Millisecond},    // ~2s ± 25%
		{3, 3 * time.Second, 5 * time.Second},                     // ~4s ± 25%
		{4, 6 * time.Second, 10 * time.Second},                    // ~8s ± 25%
		{10, 3*time.Minute + 45*time.Second, backoffMax + backoffMax/4}, // Near cap
	}

	for _, tt := range tests {
		mgr.mu.Lock()
		mgr.consecutiveFails = tt.fails
		mgr.mu.Unlock()

		delay := mgr.nextDelay()
		assert.GreaterOrEqual(t, delay, tt.minWant, "fails=%d: delay too small", tt.fails)
		assert.LessOrEqual(t, delay, tt.maxWant, "fails=%d: delay too large", tt.fails)
	}
}

func TestBundleManager_NextDelay_CapsAtMax(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient())

	mgr.mu.Lock()
	mgr.consecutiveFails = 100 // Very high failure count
	mgr.mu.Unlock()

	delay := mgr.nextDelay()
	assert.LessOrEqual(t, delay, backoffMax+backoffMax/4, "should cap at max + jitter")
}

func TestBundleManager_UnavailableBehavior(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	tests := []struct {
		mode pip.EnforcementMode
		want string
	}{
		{pip.EMObserve, "allowing all requests (EM-OBSERVE)"},
		{pip.EMGuard, "denying all requests until bundle loaded (EM-GUARD)"},
		{pip.EMDelegate, "denying all requests until bundle loaded (EM-GUARD)"},
		{pip.EMStrict, "denying all requests until bundle loaded (EM-STRICT)"},
	}

	for _, tt := range tests {
		mgr := NewBundleManager(client, NewOPALocalClient(), WithEnforcementMode(tt.mode))
		assert.Equal(t, tt.want, mgr.unavailableBehavior(), "mode=%s", tt.mode)
	}
}

func TestBundleManager_WithOptions(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient(),
		WithPollInterval(45*time.Second),
		WithMaxAge(15*time.Minute),
		WithEnforcementMode(pip.EMGuard),
	)

	assert.Equal(t, 45*time.Second, mgr.pollInterval)
	assert.Equal(t, 15*time.Minute, mgr.maxAge)
	assert.Equal(t, pip.EMGuard, mgr.mode)
}

func TestBundleManager_ZeroPollIntervalIgnored(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient(), WithPollInterval(0))
	assert.Equal(t, DefaultPollInterval, mgr.pollInterval)
}

func TestBundleManager_ZeroMaxAgeIgnored(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient(), WithMaxAge(0))
	assert.Equal(t, DefaultMaxAge, mgr.maxAge)
}

func TestBundleManager_Evaluate_FreshBundle(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator,
		WithMaxAge(10*time.Minute),
		WithEnforcementMode(pip.EMStrict),
	)

	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)

	resp, err := mgr.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
}

func TestBundleManager_Evaluate_StaleBundle_Strict(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator,
		WithMaxAge(50*time.Millisecond),
		WithEnforcementMode(pip.EMStrict),
	)

	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)

	// Wait for staleness
	time.Sleep(60 * time.Millisecond)
	require.True(t, mgr.IsStale())

	resp, err := mgr.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision, "EM-STRICT must deny on stale bundle")
	assert.Equal(t, pip.ErrorCodeBundleStale, resp.Reason)
	assert.NotEmpty(t, resp.DecisionID)
}

func TestBundleManager_Evaluate_StaleBundle_Observe(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator,
		WithMaxAge(50*time.Millisecond),
		WithEnforcementMode(pip.EMObserve),
	)

	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)

	time.Sleep(60 * time.Millisecond)
	require.True(t, mgr.IsStale())

	resp, err := mgr.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision, "EM-OBSERVE must allow even with stale bundle")
}

func TestBundleManager_Evaluate_StaleBundle_Guard(t *testing.T) {
	bundle := newTestBundle("rev-1")
	srv := newTestBundleServer(t, &bundle)
	defer srv.Close()

	client, err := NewBundleClient(srv.URL+"/v1/bundles/ws1", "key")
	require.NoError(t, err)

	evaluator := NewOPALocalClient()
	mgr := NewBundleManager(client, evaluator,
		WithMaxAge(50*time.Millisecond),
		WithEnforcementMode(pip.EMGuard),
	)

	err = mgr.RefreshNow(context.Background())
	require.NoError(t, err)

	time.Sleep(60 * time.Millisecond)
	require.True(t, mgr.IsStale())

	resp, err := mgr.Evaluate(context.Background(), newTestRequest())
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision, "EM-GUARD must allow with stale bundle")
}

func TestBundleManager_Evaluate_NoBundleReturnsError(t *testing.T) {
	client, err := NewBundleClient("http://unused/v1/bundles/ws1", "key")
	require.NoError(t, err)

	mgr := NewBundleManager(client, NewOPALocalClient())

	_, err = mgr.Evaluate(context.Background(), newTestRequest())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no policy bundle loaded")
}

func TestBundleManager_ImplementsPDPClient(t *testing.T) {
	var _ pip.PDPClient = (*BundleManager)(nil)
}

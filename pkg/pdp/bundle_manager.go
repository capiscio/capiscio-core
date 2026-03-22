package pdp

import (
	"context"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

const (
	// DefaultPollInterval is the base interval between bundle refresh attempts.
	DefaultPollInterval = 30 * time.Second

	// DefaultMaxAge is the maximum acceptable bundle age before it's considered stale.
	DefaultMaxAge = 10 * time.Minute

	// backoffBase is the initial retry delay after a fetch failure.
	backoffBase = 1 * time.Second

	// backoffMax is the maximum retry delay (caps exponential growth).
	backoffMax = 5 * time.Minute
)

// BundleManager handles background polling, hot-swapping, and staleness detection
// for OPA policy bundles. It coordinates BundleClient (pull) and OPALocalClient (evaluate).
//
// Staleness behavior per enforcement mode (PM-mandated):
//   - EM-OBSERVE:  Stale bundles are evaluated; violations logged, never blocked.
//   - EM-GUARD:    Stale bundles ARE still evaluated (allow with warning).
//   - EM-STRICT:   Stale bundles are discarded; all requests denied until fresh bundle loaded.
type BundleManager struct {
	client    *BundleClient
	evaluator *OPALocalClient

	pollInterval time.Duration
	maxAge       time.Duration
	mode         pip.EnforcementMode

	mu              sync.RWMutex
	lastRevision    string
	lastFetchAt     time.Time // tracks last successful fetch (even if revision unchanged)
	consecutiveFails int
	running         bool

	logger *slog.Logger
	cancel context.CancelFunc
}

// BundleManagerOption configures a BundleManager.
type BundleManagerOption func(*BundleManager)

// WithPollInterval sets the base polling interval.
func WithPollInterval(d time.Duration) BundleManagerOption {
	return func(m *BundleManager) {
		if d > 0 {
			m.pollInterval = d
		}
	}
}

// WithMaxAge sets the maximum acceptable bundle age before staleness.
func WithMaxAge(d time.Duration) BundleManagerOption {
	return func(m *BundleManager) {
		if d > 0 {
			m.maxAge = d
		}
	}
}

// WithEnforcementMode sets the enforcement mode for staleness behavior.
func WithEnforcementMode(em pip.EnforcementMode) BundleManagerOption {
	return func(m *BundleManager) { m.mode = em }
}

// WithManagerLogger sets the logger for the bundle manager.
func WithManagerLogger(l *slog.Logger) BundleManagerOption {
	return func(m *BundleManager) {
		if l != nil {
			m.logger = l
		}
	}
}

// NewBundleManager creates a new bundle refresh manager.
// The manager coordinates periodic bundle fetching (via BundleClient) and
// hot-swapping into the local evaluator (via OPALocalClient).
func NewBundleManager(client *BundleClient, evaluator *OPALocalClient, opts ...BundleManagerOption) *BundleManager {
	m := &BundleManager{
		client:       client,
		evaluator:    evaluator,
		pollInterval: DefaultPollInterval,
		maxAge:       DefaultMaxAge,
		mode:         pip.EMObserve,
		logger:       slog.Default(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start begins background bundle polling. Returns immediately.
// Call Stop to terminate the polling goroutine.
func (m *BundleManager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	go m.pollLoop(ctx)
}

// Stop terminates background polling. Safe to call multiple times.
func (m *BundleManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.running = false
}

// IsStale reports whether the current bundle has exceeded the max age threshold.
// Uses the last successful fetch time (including revision-unchanged fetches)
// rather than just the last bundle load time.
// Returns true if no bundle is loaded.
func (m *BundleManager) IsStale() bool {
	m.mu.RLock()
	lastFetch := m.lastFetchAt
	m.mu.RUnlock()

	if lastFetch.IsZero() {
		// No successful fetch yet; check if evaluator has a pre-loaded bundle
		age := m.evaluator.BundleAge()
		if age == 0 {
			return true // no bundle loaded
		}
		return age > m.maxAge
	}
	return time.Since(lastFetch) > m.maxAge
}

// RefreshNow triggers an immediate bundle fetch and load, outside the polling loop.
// Returns an error if the fetch or load fails.
func (m *BundleManager) RefreshNow(ctx context.Context) error {
	return m.fetchAndLoad(ctx)
}

// pollLoop is the background polling goroutine.
func (m *BundleManager) pollLoop(ctx context.Context) {
	// Attempt initial fetch immediately.
	if err := m.fetchAndLoad(ctx); err != nil {
		m.logFetchFailure(err)
	}

	for {
		delay := m.nextDelay()
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			if err := m.fetchAndLoad(ctx); err != nil {
				m.logFetchFailure(err)
			}
		}
	}
}

// fetchAndLoad pulls a bundle and loads it into the evaluator.
func (m *BundleManager) fetchAndLoad(ctx context.Context) error {
	bundle, err := m.client.Fetch(ctx)
	if err != nil {
		m.mu.Lock()
		m.consecutiveFails++
		fails := m.consecutiveFails
		m.mu.Unlock()

		// Under EM-STRICT with stale bundle, clear the evaluator to deny all requests
		if m.mode >= pip.EMStrict && m.IsStale() {
			m.logger.Warn("discarding stale bundle under EM-STRICT",
				slog.Duration("age", m.evaluator.BundleAge()),
				slog.Duration("max_age", m.maxAge),
				slog.Int("consecutive_failures", fails),
			)
			// Unload the stale bundle so evaluator returns "no bundle loaded" errors
			m.evaluator.ClearBundle()
			m.mu.Lock()
			m.lastRevision = ""
			m.mu.Unlock()
		}

		return err
	}

	// Skip reload if revision hasn't changed
	m.mu.RLock()
	sameRevision := bundle.Revision != "" && bundle.Revision == m.lastRevision
	m.mu.RUnlock()
	if sameRevision {
		m.mu.Lock()
		m.consecutiveFails = 0
		m.lastFetchAt = time.Now()
		m.mu.Unlock()
		return nil
	}

	if err := m.evaluator.LoadBundle(ctx, bundle.Modules, bundle.Data); err != nil {
		m.mu.Lock()
		m.consecutiveFails++
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	m.lastRevision = bundle.Revision
	m.consecutiveFails = 0
	m.lastFetchAt = time.Now()
	m.mu.Unlock()

	m.logger.Info("bundle refreshed",
		slog.String("revision", bundle.Revision),
		slog.Int("modules", len(bundle.Modules)),
	)

	return nil
}

// nextDelay returns the next polling interval.
// On success: uses the configured poll interval.
// On failure: exponential backoff with jitter (1s → 2s → 4s → ... → max 5m).
func (m *BundleManager) nextDelay() time.Duration {
	m.mu.RLock()
	fails := m.consecutiveFails
	m.mu.RUnlock()

	if fails == 0 {
		return m.pollInterval
	}

	// Exponential backoff: base * 2^(fails-1), capped at backoffMax
	delay := float64(backoffBase) * math.Pow(2, float64(fails-1))
	if delay > float64(backoffMax) {
		delay = float64(backoffMax)
	}

	// Add jitter: ±25% to prevent thundering herd
	jitter := delay * 0.25 * (rand.Float64()*2 - 1) //nolint:gosec // jitter doesn't need crypto rand
	delay += jitter

	return time.Duration(delay)
}

// logFetchFailure logs the bundle fetch failure with staleness context.
func (m *BundleManager) logFetchFailure(err error) {
	m.mu.RLock()
	fails := m.consecutiveFails
	m.mu.RUnlock()

	age := m.evaluator.BundleAge()
	stale := m.IsStale()

	attrs := []any{
		slog.String("error", err.Error()),
		slog.Int("consecutive_failures", fails),
		slog.Duration("next_retry", m.nextDelay()),
	}

	if age > 0 {
		attrs = append(attrs, slog.Duration("bundle_age", age))
		attrs = append(attrs, slog.Bool("stale", stale))
	}

	if !m.evaluator.HasBundle() {
		attrs = append(attrs,
			slog.String("enforcement_mode", m.mode.String()),
			slog.String("behavior", m.unavailableBehavior()),
		)
	}

	m.logger.Warn("bundle refresh failed", attrs...)
}

// unavailableBehavior returns a human-readable description of what happens
// when no bundle is available, based on enforcement mode.
func (m *BundleManager) unavailableBehavior() string {
	switch {
	case m.mode <= pip.EMObserve:
		return "allowing all requests (EM-OBSERVE)"
	case m.mode < pip.EMStrict:
		return "denying all requests until bundle loaded (EM-GUARD)"
	default:
		return "denying all requests until bundle loaded (EM-STRICT)"
	}
}

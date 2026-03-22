//go:build opa_no_wasm

package pdp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// PolicyEnforcementConfig holds all configuration needed to initialize
// the local policy decision point (PDP) stack.
type PolicyEnforcementConfig struct {
	// BundleURL is the full URL to the capiscio-server bundle endpoint.
	// If empty, local PDP is disabled and badge-only verification is used.
	BundleURL string

	// APIKey is the registry API key used for bundle endpoint authentication.
	APIKey string

	// PollInterval is how often the BundleManager polls for bundle updates.
	// Default: 30s.
	PollInterval time.Duration

	// MaxAge is the maximum acceptable bundle age before staleness.
	// Default: 10m.
	MaxAge time.Duration

	// EnforcementMode controls how policy violations are handled.
	// Default: EM-OBSERVE (log only, never block).
	EnforcementMode pip.EnforcementMode
}

// LocalPDP holds the initialized local policy enforcement stack.
// Use Client as a pip.PDPClient for policy evaluation.
// Call Stop to shut down background polling.
type LocalPDP struct {
	// Client implements pip.PDPClient for policy evaluation.
	Client *OPALocalClient

	// Manager handles background bundle refresh.
	Manager *BundleManager
}

// Stop shuts down background bundle polling gracefully.
func (l *LocalPDP) Stop() {
	if l.Manager != nil {
		l.Manager.Stop()
	}
}

// NewLocalPDP creates a configured local policy enforcement stack.
//
// If cfg.BundleURL is empty, returns (nil, nil) — no local PDP is configured
// and PEPs should fall through to badge-only verification.
//
// The returned LocalPDP starts background polling immediately.
// Call LocalPDP.Stop() when shutting down to terminate the polling goroutine.
func NewLocalPDP(ctx context.Context, cfg PolicyEnforcementConfig, opts ...BundleManagerOption) (*LocalPDP, error) {
	if cfg.BundleURL == "" {
		return nil, nil
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("pdp: CAPISCIO_API_KEY is required when CAPISCIO_BUNDLE_URL is set")
	}

	client, err := NewBundleClient(cfg.BundleURL, cfg.APIKey)
	if err != nil {
		return nil, fmt.Errorf("pdp: create bundle client: %w", err)
	}

	evaluator := NewOPALocalClient()

	// Build manager options from config, then append caller overrides.
	mgrOpts := []BundleManagerOption{
		WithEnforcementMode(cfg.EnforcementMode),
	}
	if cfg.PollInterval > 0 {
		mgrOpts = append(mgrOpts, WithPollInterval(cfg.PollInterval))
	}
	if cfg.MaxAge > 0 {
		mgrOpts = append(mgrOpts, WithMaxAge(cfg.MaxAge))
	}
	mgrOpts = append(mgrOpts, opts...)

	mgr := NewBundleManager(client, evaluator, mgrOpts...)

	// Attempt initial fetch — non-fatal under EM-OBSERVE/EM-GUARD.
	if err := mgr.RefreshNow(ctx); err != nil {
		slog.Warn("policy bundle unavailable on startup",
			slog.String("bundle_url", cfg.BundleURL),
			slog.String("enforcement_mode", cfg.EnforcementMode.String()),
			slog.String("behavior", mgr.unavailableBehavior()),
			slog.String("retry_interval", mgr.pollInterval.String()),
			slog.String("error", err.Error()),
		)
		if cfg.EnforcementMode >= pip.EMStrict {
			mgr.Stop()
			return nil, fmt.Errorf("pdp: initial bundle fetch failed under EM-STRICT: %w", err)
		}
	}

	mgr.Start(ctx)

	return &LocalPDP{
		Client:  evaluator,
		Manager: mgr,
	}, nil
}

// NewLocalPDPFromEnv reads policy enforcement configuration from environment
// variables and creates the full local PDP stack.
//
// Environment variables:
//   - CAPISCIO_BUNDLE_URL: Bundle endpoint URL (required to enable local PDP)
//   - CAPISCIO_API_KEY: Registry API key for bundle authentication
//   - CAPISCIO_BUNDLE_POLL_INTERVAL: Polling interval (Go duration, default 30s)
//   - CAPISCIO_BUNDLE_MAX_AGE: Max bundle age before stale (Go duration, default 10m)
//   - CAPISCIO_ENFORCEMENT_MODE: observe|guard|delegate|strict (default observe)
//
// If CAPISCIO_BUNDLE_URL is unset, returns (nil, nil) — no local PDP.
func NewLocalPDPFromEnv(ctx context.Context, opts ...BundleManagerOption) (*LocalPDP, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewLocalPDP(ctx, cfg, opts...)
}

// ConfigFromEnv reads PolicyEnforcementConfig from environment variables.
func ConfigFromEnv() (PolicyEnforcementConfig, error) {
	enfMode, err := pip.EnforcementModeFromEnv()
	if err != nil {
		return PolicyEnforcementConfig{}, fmt.Errorf("pdp: invalid enforcement mode: %w", err)
	}

	cfg := PolicyEnforcementConfig{
		BundleURL:       os.Getenv("CAPISCIO_BUNDLE_URL"),
		APIKey:          os.Getenv("CAPISCIO_API_KEY"),
		EnforcementMode: enfMode,
	}

	if v := os.Getenv("CAPISCIO_BUNDLE_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("pdp: invalid CAPISCIO_BUNDLE_POLL_INTERVAL %q: %w", v, err)
		}
		cfg.PollInterval = d
	}

	if v := os.Getenv("CAPISCIO_BUNDLE_MAX_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return cfg, fmt.Errorf("pdp: invalid CAPISCIO_BUNDLE_MAX_AGE %q: %w", v, err)
		}
		cfg.MaxAge = d
	}

	return cfg, nil
}

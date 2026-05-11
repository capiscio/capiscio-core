//go:build opa_no_wasm

package rpc

import (
	"context"
	"fmt"

	"github.com/capiscio/capiscio-core/v2/pkg/pdp"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// initLocalPDP initialises the local OPA-based PDP from environment variables.
// Returns (nil, nil) when CAPISCIO_BUNDLE_URL is unset (badge-only mode).
func initLocalPDP(ctx context.Context) (pip.PDPClient, error) {
	localPDP, err := pdp.NewLocalPDPFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy enforcement init: %w", err)
	}
	if localPDP != nil {
		// BundleManager.Evaluate adds staleness detection on top of the raw
		// OPA evaluation; prefer it over localPDP.Client (bare evaluator).
		return localPDP.Manager, nil
	}
	return nil, nil
}

//go:build !opa_no_wasm

package rpc

import (
	"context"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// initLocalPDP is a no-op stub when OPA support is not compiled in.
// Returns (nil, nil) — badge-only mode.
func initLocalPDP(_ context.Context) (pip.PDPClient, error) {
	return nil, nil
}

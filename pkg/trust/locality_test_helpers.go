// Package trust provides a local trust store for CA public keys.
// This file provides test infrastructure for enforcing verification locality invariants.
//
// LOCALITY INVARIANT TESTING
//
// These helpers ensure verification functions do not make synchronous network calls.
// Tests that use these helpers will fail if unexpected HTTP, DNS, or DID resolution occurs.
//
// Usage:
//
//	func TestVerifyBadgeLocalOnly(t *testing.T) {
//	    guard := trust.NewLocalityGuard(t)
//	    defer guard.Assert()
//
//	    // Your verification code here
//	    verifier := badge.NewVerifierWithTrustMaterial(trustMaterial)
//	    _, err := verifier.Verify(ctx, token)
//	    require.NoError(t, err)
//	}
package trust

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// LocalityGuard monitors for network calls during a test.
// It fails the test if any HTTP, DNS, or DID resolution occurs.
type LocalityGuard struct {
	t         testing.TB
	httpCalls int32
	dnsCalls  int32
	didCalls  int32
	failures  []string
}

// NewLocalityGuard creates a guard that fails t if network calls occur.
// Call Assert() at the end of the test to check for violations.
func NewLocalityGuard(t testing.TB) *LocalityGuard {
	g := &LocalityGuard{t: t}
	return g
}

// WrapTransport returns an http.RoundTripper that tracks all HTTP calls.
// Use this to instrument HTTP clients during tests.
func (g *LocalityGuard) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return &localityTransport{guard: g, inner: rt}
}

// BlockingTransport returns an http.RoundTripper that fails immediately
// if any HTTP call is made. Use this for strict locality testing.
func (g *LocalityGuard) BlockingTransport() http.RoundTripper {
	return &blockingTransport{guard: g}
}

// ContextWithLocalityGuard returns a context that can be used to
// pass locality checking through the call stack.
func (g *LocalityGuard) ContextWithLocalityGuard(ctx context.Context) context.Context {
	return context.WithValue(ctx, localityGuardKey{}, g)
}

// RecordHTTPCall records an HTTP call attempt.
func (g *LocalityGuard) RecordHTTPCall(url string) {
	atomic.AddInt32(&g.httpCalls, 1)
	g.failures = append(g.failures, "HTTP call to: "+url)
}

// RecordDNSCall records a DNS lookup attempt.
func (g *LocalityGuard) RecordDNSCall(host string) {
	atomic.AddInt32(&g.dnsCalls, 1)
	g.failures = append(g.failures, "DNS lookup: "+host)
}

// RecordDIDResolution records a DID resolution attempt.
func (g *LocalityGuard) RecordDIDResolution(did string) {
	atomic.AddInt32(&g.didCalls, 1)
	g.failures = append(g.failures, "DID resolution: "+did)
}

// Assert fails the test if any network calls were made.
func (g *LocalityGuard) Assert() {
	httpCount := atomic.LoadInt32(&g.httpCalls)
	dnsCount := atomic.LoadInt32(&g.dnsCalls)
	didCount := atomic.LoadInt32(&g.didCalls)

	if httpCount+dnsCount+didCount > 0 {
		g.t.Errorf("Locality invariant violated: %d HTTP calls, %d DNS calls, %d DID resolutions",
			httpCount, dnsCount, didCount)
		for _, f := range g.failures {
			g.t.Errorf("  - %s", f)
		}
	}
}

// AssertHTTPCount asserts the number of HTTP calls.
func (g *LocalityGuard) AssertHTTPCount(expected int) {
	actual := int(atomic.LoadInt32(&g.httpCalls))
	if actual != expected {
		g.t.Errorf("Expected %d HTTP calls, got %d", expected, actual)
	}
}

// HTTPCalls returns the number of HTTP calls made.
func (g *LocalityGuard) HTTPCalls() int {
	return int(atomic.LoadInt32(&g.httpCalls))
}

// DNSCalls returns the number of DNS lookups made.
func (g *LocalityGuard) DNSCalls() int {
	return int(atomic.LoadInt32(&g.dnsCalls))
}

// DIDCalls returns the number of DID resolutions made.
func (g *LocalityGuard) DIDCalls() int {
	return int(atomic.LoadInt32(&g.didCalls))
}

// =============================================================================
// HTTP Transport Wrappers
// =============================================================================

type localityTransport struct {
	guard *LocalityGuard
	inner http.RoundTripper
}

func (t *localityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.guard.RecordHTTPCall(req.URL.String())
	if t.inner != nil {
		return t.inner.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

type blockingTransport struct {
	guard *LocalityGuard
}

func (t *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	url := "<nil request>"
	if req != nil && req.URL != nil {
		url = req.URL.String()
	}
	t.guard.RecordHTTPCall(url)
	return nil, &LocalityViolationError{
		Operation: "HTTP",
		Target:    url,
		Message:   "locality invariant violation: HTTP call blocked during verification",
	}
}

// =============================================================================
// DNS Dialer Wrapper
// =============================================================================

// LocalityDialer returns a net.Dialer that records DNS lookups.
func (g *LocalityGuard) LocalityDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     g.dialDNS,
		},
	}
}

func (g *LocalityGuard) dialDNS(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	g.RecordDNSCall(host)
	return nil, &LocalityViolationError{
		Operation: "DNS",
		Target:    host,
		Message:   "locality invariant violation: DNS lookup blocked during verification",
	}
}

// =============================================================================
// Context Key
// =============================================================================

type localityGuardKey struct{}

// LocalityGuardFromContext retrieves a LocalityGuard from context.
// Returns nil if no guard is present.
func LocalityGuardFromContext(ctx context.Context) *LocalityGuard {
	if g, ok := ctx.Value(localityGuardKey{}).(*LocalityGuard); ok {
		return g
	}
	return nil
}

// =============================================================================
// Error Types
// =============================================================================

// LocalityViolationError indicates a network call was attempted during
// a locality-restricted verification operation.
type LocalityViolationError struct {
	Operation string // "HTTP", "DNS", "DID"
	Target    string // URL, hostname, or DID
	Message   string
}

func (e *LocalityViolationError) Error() string {
	return e.Message
}

// =============================================================================
// Test Helpers
// =============================================================================

// RequireNoNetworkCalls is a convenience helper that creates a guard,
// runs the function, and asserts no network calls were made.
func RequireNoNetworkCalls(t testing.TB, fn func()) {
	guard := NewLocalityGuard(t)
	fn()
	guard.Assert()
}

// AllowedNetworkCalls is a test helper that permits a specific number of
// network calls before failing.
type AllowedNetworkCalls struct {
	HTTP int
	DNS  int
	DID  int
}

// AssertWithAllowance asserts that network calls are within the allowed limits.
func (g *LocalityGuard) AssertWithAllowance(allowed AllowedNetworkCalls) {
	httpCount := int(atomic.LoadInt32(&g.httpCalls))
	dnsCount := int(atomic.LoadInt32(&g.dnsCalls))
	didCount := int(atomic.LoadInt32(&g.didCalls))

	if httpCount > allowed.HTTP {
		g.t.Errorf("Too many HTTP calls: got %d, allowed %d", httpCount, allowed.HTTP)
	}
	if dnsCount > allowed.DNS {
		g.t.Errorf("Too many DNS calls: got %d, allowed %d", dnsCount, allowed.DNS)
	}
	if didCount > allowed.DID {
		g.t.Errorf("Too many DID resolutions: got %d, allowed %d", didCount, allowed.DID)
	}
}

package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/capiscio/capiscio-core/pkg/badge"
)

// Gateway is the enforcement point for CapiscIO Trust Badges.
type Gateway struct {
	target   *url.URL
	proxy    *httputil.ReverseProxy
	verifier *badge.Verifier
}

// NewGateway creates a new Gateway instance.
func NewGateway(targetURL string, verifier *badge.Verifier) (*Gateway, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the Director to handle request modification if needed
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Set forwarding headers
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Host = target.Host
	}

	return &Gateway{
		target:   target,
		proxy:    proxy,
		verifier: verifier,
	}, nil
}

// ServeHTTP implements the http.Handler interface.
// It intercepts requests, verifies the Trust Badge, and proxies valid requests.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Extract Badge
	badgeStr := g.extractBadge(r)
	if badgeStr == "" {
		http.Error(w, "Missing CapiscIO Trust Badge", http.StatusUnauthorized)
		return
	}

	// 2. Parse Badge (assuming it's a JSON object in the header for this MVP,
	// or a JWS string that we decode. Let's assume it's the JSON struct for now
	// to match the Verifier logic which takes a struct).
	// In reality, this would likely be a JWS string that we parse.
	// Let's try to unmarshal it as the struct.
	var b badge.TrustBadge
	if err := json.Unmarshal([]byte(badgeStr), &b); err != nil {
		// If it's not JSON, maybe it's a raw JWS string?
		// For this implementation, we expect the full JSON object (VC style).
		http.Error(w, "Invalid Badge Format", http.StatusBadRequest)
		return
	}

	// 3. Verify Badge
	if err := g.verifier.Verify(r.Context(), &b); err != nil {
		log.Printf("Badge verification failed: %v", err)
		http.Error(w, fmt.Sprintf("Invalid Trust Badge: %v", err), http.StatusForbidden)
		return
	}

	// 4. Proxy Request
	g.proxy.ServeHTTP(w, r)
}

// extractBadge retrieves the badge from the request headers.
// It looks for 'X-Capiscio-Badge'.
func (g *Gateway) extractBadge(r *http.Request) string {
	return r.Header.Get("X-Capiscio-Badge")
}

// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// NetworkRequest represents a request to access a network resource.
type NetworkRequest struct {
	// URL is the network resource being accessed.
	URL string

	// Method is the HTTP method (GET, POST, etc.) for HTTP requests.
	// Empty for non-HTTP protocols.
	Method string

	// Protocol is the network protocol (http, https, tcp, etc.).
	Protocol string

	// Description is a human-readable description of the access.
	Description string
}

// Domain implements Request.
func (r *NetworkRequest) Domain() string {
	return "network"
}

// Capability implements Request.
func (r *NetworkRequest) Capability() string {
	return fmt.Sprintf("network:%s:%s", r.Method, r.URL)
}

// NetworkHookConfig configures the network mediation hook.
type NetworkHookConfig struct {
	// Logger for mediation operations.
	Logger Logger

	// Emitter for RFC-011 events.
	Emitter EventEmitter

	// AllowedHosts is a list of hostnames that are always allowed.
	// Supports wildcards: "*.example.com" matches all subdomains.
	AllowedHosts []string

	// DeniedHosts is a list of hostnames that are always denied.
	// Takes precedence over AllowedHosts.
	DeniedHosts []string

	// AllowedProtocols is a list of allowed protocols.
	// Default: ["http", "https"]
	AllowedProtocols []string

	// DefaultDeny rejects requests when no explicit grant is found.
	// Default: true (safer for network access)
	DefaultDeny bool

	// RequireEnvelope requires an authority envelope for network access.
	// Default: false
	RequireEnvelope bool

	// BlockPrivateNetworks blocks access to RFC 1918 private networks.
	// Default: true
	BlockPrivateNetworks bool
}

// privateNetworkPrefixes are RFC 1918 and similar private/local addresses.
var privateNetworkPrefixes = []string{
	"10.",
	"172.16.", "172.17.", "172.18.", "172.19.",
	"172.20.", "172.21.", "172.22.", "172.23.",
	"172.24.", "172.25.", "172.26.", "172.27.",
	"172.28.", "172.29.", "172.30.", "172.31.",
	"192.168.",
	"127.",
	"169.254.", // Link-local
	"::1",      // IPv6 localhost
	"fe80:",    // IPv6 link-local
	"fc00:",    // IPv6 unique local
	"fd00:",    // IPv6 unique local
}

// NetworkHook mediates network access requests.
type NetworkHook struct {
	config  NetworkHookConfig
	logger  Logger
	emitter EventEmitter
}

// NewNetworkHook creates a network mediation hook.
func NewNetworkHook(config NetworkHookConfig) *NetworkHook {
	h := &NetworkHook{
		config:  config,
		logger:  config.Logger,
		emitter: config.Emitter,
	}
	if h.logger == nil {
		h.logger = noopLogger{}
	}
	if h.emitter == nil {
		h.emitter = noopEmitter{}
	}
	// Set defaults
	if len(h.config.AllowedProtocols) == 0 {
		h.config.AllowedProtocols = []string{"http", "https"}
	}
	return h
}

// Mediate evaluates a network access request.
func (h *NetworkHook) Mediate(ctx context.Context, mctx *Context, request Request) (*Result, error) {
	netReq, ok := request.(*NetworkRequest)
	if !ok {
		return nil, fmt.Errorf("NetworkHook requires *NetworkRequest, got %T", request)
	}

	// Parse and canonicalize URL
	parsed, err := url.Parse(netReq.URL)
	if err != nil {
		result := DenyResult("builtin:invalid_url", fmt.Sprintf("invalid URL: %v", err))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	host := parsed.Hostname()
	protocol := parsed.Scheme
	if netReq.Protocol != "" {
		protocol = netReq.Protocol
	}

	h.logger.Debug("mediating network request",
		"url", netReq.URL,
		"host", host,
		"protocol", protocol,
		"subject", mctx.SubjectDID,
	)

	// 0. Check trust material availability
	if !mctx.HasTrustMaterial() {
		result := DenyResult("builtin:no_trust_material", "trust material not available")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 1. Check authentication
	if !mctx.HasBadge() {
		result := DenyResult("builtin:unauthenticated", "no valid badge presented")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 2. Check RequireEnvelope
	if h.config.RequireEnvelope && !mctx.HasEnvelope() {
		result := DenyResult("builtin:envelope_required", "authority envelope required for network access")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 3. Check protocol
	if !h.isProtocolAllowed(protocol) {
		result := DenyResult("builtin:protocol_denied",
			fmt.Sprintf("protocol %q is not allowed", protocol))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 4. Check private networks
	if h.config.BlockPrivateNetworks && h.isPrivateNetwork(host) {
		result := DenyResult("builtin:private_network",
			fmt.Sprintf("access to private network address %q is denied", host))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 5. Check DeniedHosts
	for _, denied := range h.config.DeniedHosts {
		if h.matchHost(host, denied) {
			result := DenyResult("config:denied_host",
				fmt.Sprintf("access to host %q is denied by configuration", host))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 6. Check AllowedHosts
	for _, allowed := range h.config.AllowedHosts {
		if h.matchHost(host, allowed) {
			result := AllowResult("config:allowed_host",
				fmt.Sprintf("access to host %q is allowed by configuration", host))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 7. Check envelope capabilities
	if mctx.HasEnvelope() {
		if mctx.CapabilitySatisfied("network.*") || mctx.CapabilitySatisfied("network.http") {
			result := AllowResult("envelope:capability_grant",
				fmt.Sprintf("capability granted for network access to %q", host))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 8. Apply default policy
	if h.config.DefaultDeny {
		result := DenyResult("builtin:default_deny",
			fmt.Sprintf("no explicit grant for network access to %q", host))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// Default allow (only if DefaultDeny = false)
	result := AllowResult("builtin:default_allow",
		fmt.Sprintf("authenticated caller may access %q", host))
	h.emitter.EmitDecision(mctx, result, request)
	return result, nil
}

// isProtocolAllowed checks if the protocol is in the allowed list.
func (h *NetworkHook) isProtocolAllowed(protocol string) bool {
	for _, allowed := range h.config.AllowedProtocols {
		if strings.EqualFold(protocol, allowed) {
			return true
		}
	}
	return false
}

// isPrivateNetwork checks if the host is a private/local network address.
func (h *NetworkHook) isPrivateNetwork(host string) bool {
	// Check localhost by name
	if host == "localhost" || host == "localhost.localdomain" {
		return true
	}

	// Check IP prefixes
	for _, prefix := range privateNetworkPrefixes {
		if strings.HasPrefix(host, prefix) {
			return true
		}
	}

	return false
}

// matchHost checks if a host matches a pattern.
func (h *NetworkHook) matchHost(host, pattern string) bool {
	// Exact match
	if host == pattern {
		return true
	}

	// Wildcard subdomain match (*.example.com)
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		if strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}

	return false
}

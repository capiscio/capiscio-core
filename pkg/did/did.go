// Package did provides utilities for parsing and working with did:web identifiers.
// See RFC-002: Trust Badge Specification §6.
package did

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Common errors returned by this package.
var (
	ErrInvalidDID        = errors.New("invalid DID format")
	ErrUnsupportedMethod = errors.New("unsupported DID method (only did:web is supported)")
	ErrMissingAgentID    = errors.New("missing agent ID in DID")
)

// DID represents a parsed did:web identifier.
// Format: did:web:<domain>:agents:<agent-id>
type DID struct {
	// Method is the DID method (always "web" for this package).
	Method string

	// Domain is the domain hosting the DID Document.
	Domain string

	// Path segments after the domain (e.g., ["agents", "my-agent-001"]).
	PathSegments []string

	// AgentID is the agent identifier (extracted from path).
	AgentID string

	// Raw is the original DID string.
	Raw string
}

// Parse parses a did:web identifier into its components.
// Returns ErrInvalidDID if the format is invalid.
// Returns ErrUnsupportedMethod if the method is not "web".
//
// Examples:
//   - did:web:registry.capisc.io:agents:my-agent-001
//   - did:web:example.com:agents:test-agent
func Parse(did string) (*DID, error) {
	if did == "" {
		return nil, ErrInvalidDID
	}

	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("%w: expected at least 3 parts, got %d", ErrInvalidDID, len(parts))
	}

	if parts[0] != "did" {
		return nil, fmt.Errorf("%w: must start with 'did:'", ErrInvalidDID)
	}

	if parts[1] != "web" {
		return nil, fmt.Errorf("%w: got did:%s", ErrUnsupportedMethod, parts[1])
	}

	// URL-decode the domain (did:web uses percent-encoding for special chars)
	domain, err := url.PathUnescape(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid domain encoding: %v", ErrInvalidDID, err)
	}

	if domain == "" {
		return nil, fmt.Errorf("%w: empty domain", ErrInvalidDID)
	}

	// Remaining parts are path segments
	pathSegments := parts[3:]

	// Extract agent ID: look for "agents" segment and take the next one
	var agentID string
	for i, seg := range pathSegments {
		if seg == "agents" && i+1 < len(pathSegments) {
			agentID = pathSegments[i+1]
			break
		}
	}

	return &DID{
		Method:       "web",
		Domain:       domain,
		PathSegments: pathSegments,
		AgentID:      agentID,
		Raw:          did,
	}, nil
}

// String returns the canonical DID string.
func (d *DID) String() string {
	if d.Raw != "" {
		return d.Raw
	}
	// Reconstruct from components
	parts := []string{"did", d.Method, url.PathEscape(d.Domain)}
	parts = append(parts, d.PathSegments...)
	return strings.Join(parts, ":")
}

// DocumentURL returns the HTTPS URL for the DID Document per did:web spec.
// did:web:registry.capisc.io:agents:my-agent-001
//
//	→ https://registry.capisc.io/agents/my-agent-001/did.json
func (d *DID) DocumentURL() string {
	// Build the path from segments
	path := strings.Join(d.PathSegments, "/")
	if path != "" {
		path = "/" + path
	}
	return fmt.Sprintf("https://%s%s/did.json", d.Domain, path)
}

// NewAgentDID constructs a did:web identifier for an agent.
//
// Parameters:
//   - domain: The domain hosting the agent (e.g., "registry.capisc.io")
//   - agentID: The unique agent identifier (e.g., "my-agent-001")
//
// Returns: did:web:<domain>:agents:<agentID>
func NewAgentDID(domain, agentID string) string {
	// URL-encode the domain if it contains special characters
	encodedDomain := url.PathEscape(domain)
	// Colons in the domain need to be encoded per did:web spec
	encodedDomain = strings.ReplaceAll(encodedDomain, ":", "%3A")
	return fmt.Sprintf("did:web:%s:agents:%s", encodedDomain, agentID)
}

// IsAgentDID returns true if the DID follows the CapiscIO agent DID pattern.
// Pattern: did:web:<domain>:agents:<id>
func (d *DID) IsAgentDID() bool {
	if len(d.PathSegments) < 2 {
		return false
	}
	return d.PathSegments[0] == "agents" && d.AgentID != ""
}

// DefaultDomain is the default domain for CapiscIO-hosted agents.
const DefaultDomain = "registry.capisc.io"

// NewCapiscIOAgentDID constructs a did:web for an agent on the CapiscIO registry.
// Shorthand for NewAgentDID(DefaultDomain, agentID).
func NewCapiscIOAgentDID(agentID string) string {
	return NewAgentDID(DefaultDomain, agentID)
}

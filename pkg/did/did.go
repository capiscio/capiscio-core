// Package did provides utilities for parsing and working with DID identifiers.
// Supports did:web (RFC-002 §6.1) and did:key (RFC-002 §6.6) methods.
// See RFC-002: Trust Badge Specification v1.1.
package did

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Common errors returned by this package.
var (
	ErrInvalidDID         = errors.New("invalid DID format")
	ErrUnsupportedMethod  = errors.New("unsupported DID method (only did:web and did:key supported)")
	ErrMissingAgentID     = errors.New("missing agent ID in DID")
	ErrInvalidKeyDID      = errors.New("invalid did:key format")
	ErrUnsupportedKeyType = errors.New("unsupported key type in did:key (only Ed25519 supported)")
)

// Multicodec constants for did:key
const (
	// Ed25519MulticodecPrefix is the multicodec prefix for Ed25519 public keys (0xed01)
	Ed25519MulticodecPrefix = 0xed01

	// Ed25519PublicKeySize is the size of an Ed25519 public key in bytes
	Ed25519PublicKeySize = 32
)

// DID represents a parsed DID identifier.
// Supports both did:web and did:key methods.
//
// For did:web: did:web:<domain>:agents:<agent-id>
// For did:key: did:key:z<base58btc(multicodec || public_key)>
type DID struct {
	// Method is the DID method ("web" or "key").
	Method string

	// Domain is the domain hosting the DID Document (did:web only).
	Domain string

	// Path segments after the domain (did:web only, e.g., ["agents", "my-agent-001"]).
	PathSegments []string

	// AgentID is the agent identifier (did:web only, extracted from path).
	AgentID string

	// PublicKey is the Ed25519 public key (did:key only, 32 bytes).
	PublicKey []byte

	// Raw is the original DID string.
	Raw string
}

// Parse parses a DID identifier into its components.
// Supports both did:web and did:key methods.
//
// Returns ErrInvalidDID if the format is invalid.
// Returns ErrUnsupportedMethod if the method is not "web" or "key".
//
// Examples:
//   - did:web:registry.capisc.io:agents:my-agent-001
//   - did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
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

	method := parts[1]
	switch method {
	case "web":
		return parseWebDID(parts)
	case "key":
		return parseKeyDID(parts)
	default:
		return nil, fmt.Errorf("%w: got did:%s", ErrUnsupportedMethod, method)
	}
}

// parseWebDID parses a did:web identifier.
func parseWebDID(parts []string) (*DID, error) {
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
		Raw:          strings.Join(parts, ":"),
	}, nil
}

// parseKeyDID parses a did:key identifier.
// Format: did:key:z<base58btc(0xed01 || ed25519_public_key)>
func parseKeyDID(parts []string) (*DID, error) {
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: did:key must have exactly 3 parts", ErrInvalidKeyDID)
	}

	multibaseValue := parts[2]
	if multibaseValue == "" {
		return nil, fmt.Errorf("%w: empty key identifier", ErrInvalidKeyDID)
	}

	// did:key uses multibase encoding, 'z' prefix indicates base58btc
	if multibaseValue[0] != 'z' {
		return nil, fmt.Errorf("%w: expected 'z' (base58btc) prefix, got '%c'", ErrInvalidKeyDID, multibaseValue[0])
	}

	// Decode the base58btc-encoded value (skip the 'z' prefix)
	decoded, err := base58Decode(multibaseValue[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base58btc encoding: %v", ErrInvalidKeyDID, err)
	}

	// Check for Ed25519 multicodec prefix (0xed, 0x01)
	if len(decoded) < 2 {
		return nil, fmt.Errorf("%w: decoded value too short", ErrInvalidKeyDID)
	}

	// Multicodec is varint-encoded; Ed25519 is 0xed01 which encodes as [0xed, 0x01]
	if decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("%w: expected Ed25519 multicodec (0xed01), got 0x%02x%02x", ErrUnsupportedKeyType, decoded[0], decoded[1])
	}

	// Extract the public key (after the 2-byte prefix)
	publicKey := decoded[2:]
	if len(publicKey) != Ed25519PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key must be %d bytes, got %d", ErrInvalidKeyDID, Ed25519PublicKeySize, len(publicKey))
	}

	return &DID{
		Method:    "key",
		PublicKey: publicKey,
		Raw:       strings.Join(parts, ":"),
	}, nil
}

// String returns the canonical DID string.
func (d *DID) String() string {
	if d.Raw != "" {
		return d.Raw
	}
	// Reconstruct from components
	if d.Method == "key" && len(d.PublicKey) > 0 {
		return NewKeyDID(d.PublicKey)
	}
	parts := []string{"did", d.Method, url.PathEscape(d.Domain)}
	parts = append(parts, d.PathSegments...)
	return strings.Join(parts, ":")
}

// DocumentURL returns the HTTPS URL for the DID Document per did:web spec.
// did:web:registry.capisc.io:agents:my-agent-001
//
//	→ https://registry.capisc.io/agents/my-agent-001/did.json
//
// Returns empty string for did:key (no remote document).
// Uses HTTP for localhost domains, HTTPS otherwise.
func (d *DID) DocumentURL() string {
	if d.Method != "web" {
		return "" // did:key doesn't have a remote document
	}
	// Build the path from segments
	path := strings.Join(d.PathSegments, "/")
	if path != "" {
		path = "/" + path
	}
	
	// Domain should already be URL-decoded by parseWebDID, but ensure it's valid for URL construction
	// In case it wasn't decoded (e.g., created manually), decode it here
	domain := d.Domain
	if decoded, err := url.PathUnescape(domain); err == nil {
		domain = decoded
	}
	
	// Use HTTP for localhost, HTTPS for everything else
	scheme := "https"
	if strings.HasPrefix(domain, "localhost") || strings.HasPrefix(domain, "127.0.0.1") {
		scheme = "http"
	}
	
	return fmt.Sprintf("%s://%s%s/did.json", scheme, domain, path)
}

// IsKeyDID returns true if this is a did:key identifier.
func (d *DID) IsKeyDID() bool {
	return d.Method == "key"
}

// IsWebDID returns true if this is a did:web identifier.
func (d *DID) IsWebDID() bool {
	return d.Method == "web"
}

// GetPublicKey returns the Ed25519 public key for did:key identifiers.
// Returns nil for did:web identifiers.
func (d *DID) GetPublicKey() ed25519.PublicKey {
	if d.Method != "key" || len(d.PublicKey) != Ed25519PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(d.PublicKey)
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

// NewKeyDID constructs a did:key identifier from an Ed25519 public key.
// Format: did:key:z<base58btc(0xed01 || public_key)>
//
// Parameters:
//   - publicKey: Ed25519 public key (32 bytes)
//
// Returns: did:key:z6Mk... formatted DID string
func NewKeyDID(publicKey []byte) string {
	if len(publicKey) != Ed25519PublicKeySize {
		return "" // Invalid key size
	}

	// Build the multicodec-prefixed value: 0xed01 || public_key
	prefixed := make([]byte, 2+len(publicKey))
	prefixed[0] = 0xed
	prefixed[1] = 0x01
	copy(prefixed[2:], publicKey)

	// Encode as base58btc with 'z' multibase prefix
	encoded := "z" + base58Encode(prefixed)

	return "did:key:" + encoded
}

// PublicKeyFromKeyDID extracts the Ed25519 public key from a did:key identifier.
// Returns the 32-byte public key or an error if the DID is invalid.
func PublicKeyFromKeyDID(didStr string) (ed25519.PublicKey, error) {
	parsed, err := Parse(didStr)
	if err != nil {
		return nil, err
	}

	if parsed.Method != "key" {
		return nil, fmt.Errorf("%w: expected did:key, got did:%s", ErrInvalidKeyDID, parsed.Method)
	}

	if len(parsed.PublicKey) != Ed25519PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key size", ErrInvalidKeyDID)
	}

	return ed25519.PublicKey(parsed.PublicKey), nil
}

// base58Alphabet is the Bitcoin Base58 alphabet
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes a byte slice to base58btc (Bitcoin alphabet).
func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zeros
	leadingZeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Allocate enough space for the result
	// base58 encoding increases size by approximately 137/100
	size := len(input)*138/100 + 1
	buf := make([]byte, size)

	// Process each byte
	var length int
	for _, b := range input {
		carry := int(b)
		for i := 0; i < length || carry != 0; i++ {
			if i < length {
				carry += 256 * int(buf[i])
			}
			buf[i] = byte(carry % 58)
			carry /= 58
			if i >= length {
				length = i + 1
			}
		}
	}

	// Build result string (reverse order)
	result := make([]byte, leadingZeros+length)

	// Add leading '1's for each leading zero byte
	for i := 0; i < leadingZeros; i++ {
		result[i] = '1'
	}

	// Add encoded characters in reverse
	for i := 0; i < length; i++ {
		result[leadingZeros+i] = base58Alphabet[buf[length-1-i]]
	}

	return string(result)
}

// base58Decode decodes a base58btc string to bytes.
func base58Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}

	// Build alphabet index map
	alphabetMap := make(map[rune]int)
	for i, c := range base58Alphabet {
		alphabetMap[c] = i
	}

	// Count leading '1's (representing leading zero bytes)
	leadingOnes := 0
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingOnes++
	}

	// Allocate space for result
	// Each base58 character represents slightly less than 1 byte
	size := len(input)*733/1000 + 1
	buf := make([]byte, size)

	// Process each character
	var length int
	for _, c := range input {
		val, ok := alphabetMap[c]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}

		carry := val
		for i := 0; i < length || carry != 0; i++ {
			if i < length {
				carry += 58 * int(buf[i])
			}
			buf[i] = byte(carry % 256)
			carry /= 256
			if i >= length {
				length = i + 1
			}
		}
	}

	// Build result (reverse order)
	result := make([]byte, leadingOnes+length)

	// Add leading zeros
	for i := 0; i < leadingOnes; i++ {
		result[i] = 0
	}

	// Add decoded bytes in reverse
	for i := 0; i < length; i++ {
		result[leadingOnes+i] = buf[length-1-i]
	}

	return result, nil
}

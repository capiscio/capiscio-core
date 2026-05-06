package did

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebResolver errors.
var (
	ErrSSRFBlocked       = errors.New("SSRF: did:web target resolves to blocked address")
	ErrHTTPRequired      = errors.New("did:web requires HTTPS (HTTP not allowed in production)")
	ErrDocumentTooLarge  = errors.New("DID document exceeds maximum size")
	ErrKeyNotFound       = errors.New("key ID not found in DID document")
	ErrUnsupportedVMType = errors.New("unsupported verification method type")
	ErrDocumentFetch     = errors.New("failed to fetch DID document")
)

// DefaultMaxDocSize is the maximum DID document size (64KB).
const DefaultMaxDocSize = 64 * 1024

// DefaultResolveTimeout is the default HTTP timeout for DID document fetches.
const DefaultResolveTimeout = 10 * time.Second

// DefaultCacheTTL is the default cache duration for resolved documents.
const DefaultCacheTTL = 5 * time.Minute

// WebResolver resolves did:web identifiers by fetching DID documents over HTTPS.
type WebResolver struct {
	// Client is the HTTP client to use. If nil, a default client with
	// SSRF-safe dialer and timeout is created.
	Client *http.Client

	// MaxDocSize is the maximum response body size in bytes.
	// Default: 64KB.
	MaxDocSize int

	// CacheTTL is the duration to cache resolved documents.
	// Default: 5 minutes. Set to 0 to disable caching.
	CacheTTL time.Duration

	// AllowHTTP allows HTTP (non-TLS) for testing. MUST be false in production.
	AllowHTTP bool

	cache   sync.Map // map[string]*cacheEntry
	initOnce sync.Once
	client   *http.Client
}

type cacheEntry struct {
	doc       *Document
	expiresAt time.Time
}

// Resolve fetches the DID document for a did:web identifier and extracts
// the public key matching the given key ID fragment.
func (r *WebResolver) Resolve(ctx context.Context, didStr string, kid string) (crypto.PublicKey, error) {
	r.initOnce.Do(r.init)

	parsed, err := Parse(didStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID: %w", err)
	}
	if !parsed.IsWebDID() {
		return nil, fmt.Errorf("expected did:web, got did:%s", parsed.Method)
	}

	docURL := parsed.DocumentURL()
	if docURL == "" {
		return nil, fmt.Errorf("failed to construct document URL for %q", didStr)
	}

	// SSRF: Reject HTTP in production mode
	if !r.AllowHTTP && strings.HasPrefix(docURL, "http://") {
		return nil, fmt.Errorf("%w: %s", ErrHTTPRequired, docURL)
	}

	// Check cache
	doc, err := r.resolveDocument(ctx, docURL)
	if err != nil {
		return nil, err
	}

	// Extract key by fragment
	return r.extractKey(doc, didStr, kid)
}

func (r *WebResolver) init() {
	maxDoc := r.MaxDocSize
	if maxDoc == 0 {
		maxDoc = DefaultMaxDocSize
	}
	r.MaxDocSize = maxDoc

	if r.CacheTTL == 0 {
		r.CacheTTL = DefaultCacheTTL
	}

	if r.Client != nil {
		r.client = r.Client
	} else {
		r.client = &http.Client{
			Timeout: DefaultResolveTimeout,
			Transport: &http.Transport{
				DialContext: ssrfSafeDialer(),
				TLSHandshakeTimeout: 5 * time.Second,
			},
			// Do not follow redirects — prevents SSRF via redirect to internal IP
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
}

func (r *WebResolver) resolveDocument(ctx context.Context, docURL string) (*Document, error) {
	// Check cache
	if r.CacheTTL > 0 {
		if entry, ok := r.cache.Load(docURL); ok {
			ce := entry.(*cacheEntry)
			if time.Now().Before(ce.expiresAt) {
				return ce.doc, nil
			}
			r.cache.Delete(docURL)
		}
	}

	// Fetch document
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDocumentFetch, err)
	}
	req.Header.Set("Accept", "application/did+json, application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDocumentFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d from %s", ErrDocumentFetch, resp.StatusCode, docURL)
	}

	// Enforce size limit
	limitedReader := io.LimitReader(resp.Body, int64(r.MaxDocSize)+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("%w: read error: %v", ErrDocumentFetch, err)
	}
	if len(body) > r.MaxDocSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrDocumentTooLarge, len(body), r.MaxDocSize)
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrDocumentFetch, err)
	}

	// Cache the result
	if r.CacheTTL > 0 {
		r.cache.Store(docURL, &cacheEntry{
			doc:       &doc,
			expiresAt: time.Now().Add(r.CacheTTL),
		})
	}

	return &doc, nil
}

func (r *WebResolver) extractKey(doc *Document, didStr string, kid string) (crypto.PublicKey, error) {
	// Build the expected key ID: did#kid or just kid
	var targetID string
	if kid != "" {
		if strings.HasPrefix(kid, didStr+"#") || strings.HasPrefix(kid, "#") {
			targetID = kid
		} else {
			targetID = didStr + "#" + kid
		}
	}

	for _, vm := range doc.VerificationMethod {
		// Match by key ID or take the first Ed25519 key if no kid specified
		if kid != "" {
			// Check various ID formats
			if vm.ID != targetID && vm.ID != "#"+kid && vm.ID != kid {
				continue
			}
		}

		// Extract key based on verification method type
		switch vm.Type {
		case "Ed25519VerificationKey2020", "Ed25519VerificationKey2018":
			if vm.PublicKeyMultibase != "" {
				return decodeMultibaseKey(vm.PublicKeyMultibase)
			}
		case "JsonWebKey2020":
			if vm.PublicKeyJwk != nil {
				return decodeJWK(vm.PublicKeyJwk)
			}
		default:
			// Try both formats for unknown types
			if vm.PublicKeyMultibase != "" {
				return decodeMultibaseKey(vm.PublicKeyMultibase)
			}
			if vm.PublicKeyJwk != nil {
				return decodeJWK(vm.PublicKeyJwk)
			}
			continue
		}
	}

	if kid != "" {
		return nil, fmt.Errorf("%w: %s#%s", ErrKeyNotFound, didStr, kid)
	}
	return nil, fmt.Errorf("%w: no verification methods in document for %s", ErrKeyNotFound, didStr)
}

// decodeMultibaseKey decodes a multibase-encoded Ed25519 public key.
// Supports 'z' (base58btc) prefix with Ed25519 multicodec (0xed01).
func decodeMultibaseKey(multibase string) (crypto.PublicKey, error) {
	if len(multibase) == 0 {
		return nil, fmt.Errorf("%w: empty publicKeyMultibase", ErrUnsupportedVMType)
	}
	if multibase[0] != 'z' {
		return nil, fmt.Errorf("%w: unsupported multibase prefix '%c' (only 'z'/base58btc supported)", ErrUnsupportedVMType, multibase[0])
	}

	decoded, err := base58Decode(multibase[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: base58 decode failed: %v", ErrUnsupportedVMType, err)
	}

	// Check for Ed25519 multicodec prefix
	if len(decoded) < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("%w: expected Ed25519 multicodec prefix (0xed01)", ErrUnsupportedVMType)
	}

	pubKeyBytes := decoded[2:]
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key must be %d bytes, got %d", ErrUnsupportedVMType, ed25519.PublicKeySize, len(pubKeyBytes))
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// decodeJWK decodes a JWK-encoded Ed25519 public key (OKP curve).
func decodeJWK(jwk *JWK) (crypto.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("%w: JWK must be OKP/Ed25519, got %s/%s", ErrUnsupportedVMType, jwk.Kty, jwk.Crv)
	}
	if jwk.X == "" {
		return nil, fmt.Errorf("%w: JWK missing 'x' field", ErrUnsupportedVMType)
	}

	// JWK uses base64url encoding (no padding)
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64url in JWK.x: %v", ErrUnsupportedVMType, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key must be %d bytes, got %d", ErrUnsupportedVMType, ed25519.PublicKeySize, len(pubKeyBytes))
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// ssrfSafeDialer returns a DialContext function that blocks connections to
// private/internal IP addresses (RFC-008 §17.1 SSRF protection).
func ssrfSafeDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid address %q", ErrSSRFBlocked, addr)
		}

		// Block known dangerous hostnames
		lowerHost := strings.ToLower(host)
		if lowerHost == "localhost" || lowerHost == "metadata.google.internal" ||
			lowerHost == "169.254.169.254" {
			return nil, fmt.Errorf("%w: blocked hostname %q", ErrSSRFBlocked, host)
		}

		// Resolve hostname and check IPs
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %q: %w", host, err)
		}

		for _, ip := range ips {
			if isPrivateIP(ip.IP) {
				return nil, fmt.Errorf("%w: %q resolves to private IP %s", ErrSSRFBlocked, host, ip.IP)
			}
		}

		return dialer.DialContext(ctx, network, addr)
	}
}

// isPrivateIP checks if an IP address is in a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	// Loopback
	if ip.IsLoopback() {
		return true
	}
	// Link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Private IPv4 ranges
	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("169.254.0.0/16")},  // Link-local IPv4
		{mustParseCIDR("fc00::/7")},          // IPv6 unique local
		{mustParseCIDR("fe80::/10")},         // IPv6 link-local
	}
	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR %q: %v", s, err))
	}
	return network
}

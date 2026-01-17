package mcp

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/pop"
)

// ServerIdentityVerifier implements RFC-007 server identity verification.
// It uses the same badge.Verifier as agent identity verification for consistency.
//
// Per RFC-007 §3: A Server Badge is a Trust Badge (RFC-002) issued for a server DID.
// This means MCP servers use the SAME identity infrastructure as agents:
// - Same DID patterns (did:web:domain:servers:id vs did:web:domain:agents:id)
// - Same Trust Badge format
// - Same verification workflow via badge.Verifier
//
// The verification has two phases:
// 1. Badge verification: Verify the badge is valid and signed by trusted CA
// 2. PoP verification: Verify the server controls the DID's private key
//
// RFC-007 PoP is embedded in the MCP handshake (initialize), NOT via CA endpoints:
// - Client sends nonce in initialize request _meta
// - Server returns signature in initialize response _meta
// - No dependency on /badge/challenge endpoints
type ServerIdentityVerifier struct {
	badgeVerifier *badge.Verifier
	sessionCache  *pop.SessionCache
}

// NewServerIdentityVerifier creates a new server identity verifier.
// The badgeVerifier is the same verifier used for agent badges - this ensures
// consistent identity verification across both agents and MCP servers.
func NewServerIdentityVerifier(badgeVerifier *badge.Verifier) *ServerIdentityVerifier {
	return &ServerIdentityVerifier{
		badgeVerifier: badgeVerifier,
		sessionCache:  pop.NewSessionCache(nil), // Use defaults
	}
}

// NewServerIdentityVerifierWithConfig creates a verifier with custom cache config
func NewServerIdentityVerifierWithConfig(badgeVerifier *badge.Verifier, cacheConfig *pop.CacheConfig) *ServerIdentityVerifier {
	return &ServerIdentityVerifier{
		badgeVerifier: badgeVerifier,
		sessionCache:  pop.NewSessionCache(cacheConfig),
	}
}

// VerifyServerIdentity implements RFC-007 §7.2 server identity verification algorithm.
//
// RFC-007 defines Server Badges as Trust Badges where sub = server DID.
// This method verifies the server badge using the same badge.Verifier as agents.
//
// The algorithm classifies servers into THREE states:
// - VERIFIED_PRINCIPAL: DID + badge verified + PoP verified (full trust)
// - DECLARED_PRINCIPAL: DID + badge verified, PoP not performed (partial trust)
// - UNVERIFIED_ORIGIN: Missing DID, missing badge, or verification failed
//
// For VERIFIED_PRINCIPAL, also call VerifyPoP with the PoP data from initialize.
func (v *ServerIdentityVerifier) VerifyServerIdentity(
	ctx context.Context,
	serverDID string,
	serverBadgeJWS string,
	transportOrigin string,
	config *VerifyConfig,
) (*VerifyResult, error) {
	if config == nil {
		config = DefaultVerifyConfig()
	}

	result := &VerifyResult{
		ServerID: serverDID,
	}

	// Step 1: Check if any identity was disclosed (RFC-007 §7.2.1)
	if serverDID == "" {
		result.State = ServerStateUnverifiedOrigin
		result.ErrorCode = ServerErrorCodeDIDMissing
		result.ErrorDetail = "no server DID disclosed"
		return result, nil
	}

	// Step 2: Check for server badge (RFC-007 §7.2.2)
	// Per RFC-007 §7, DID without badge = DECLARED_PRINCIPAL (identity declared but not verified)
	if serverBadgeJWS == "" {
		result.State = ServerStateDeclaredPrincipal
		// No error - this is a valid state
		return result, nil
	}

	// Step 3: Validate DID format using pkg/did
	parsedDID, err := did.Parse(serverDID)
	if err != nil {
		result.State = ServerStateUnverifiedOrigin
		result.ErrorCode = ServerErrorCodeDIDResolutionFailed
		result.ErrorDetail = fmt.Sprintf("invalid DID format: %v", err)
		return result, nil
	}

	// Step 4: Check allowed DID methods
	if len(config.AllowedDIDMethods) > 0 {
		if !isMethodAllowed(parsedDID.Method, config.AllowedDIDMethods) {
			result.State = ServerStateUnverifiedOrigin
			result.ErrorCode = ServerErrorCodeDIDResolutionFailed
			result.ErrorDetail = fmt.Sprintf("DID method %q not allowed", parsedDID.Method)
			return result, nil
		}
	}

	// Step 5: Check origin binding for did:web (if required) - RFC-007 §7.2.6
	if config.RequireOriginBinding && parsedDID.IsWebDID() {
		if !checkDIDOriginBinding(parsedDID, transportOrigin) {
			result.State = ServerStateUnverifiedOrigin
			result.ErrorCode = ServerErrorCodeOriginMismatch
			result.ErrorDetail = fmt.Sprintf("did:web %s does not match origin %s", serverDID, transportOrigin)
			return result, nil
		}
	}

	// Step 6: Verify server badge using badge.Verifier (RFC-007 §7.2.3)
	// This is the SAME verification path as agent badges - unified identity infrastructure
	badgeResult, err := v.badgeVerifier.VerifyWithOptions(ctx, serverBadgeJWS, badge.VerifyOptions{
		// Server badges use the same verification as agent badges
	})
	if err != nil {
		result.State = ServerStateUnverifiedOrigin
		result.ErrorCode = ServerErrorCodeBadgeInvalid
		result.ErrorDetail = fmt.Sprintf("badge verification failed: %v", err)
		return result, nil
	}

	// Step 7: Verify badge subject matches disclosed DID (RFC-007 §7.2.3)
	if badgeResult.Claims.Subject != serverDID {
		result.State = ServerStateUnverifiedOrigin
		result.ErrorCode = ServerErrorCodeDIDMismatch
		result.ErrorDetail = fmt.Sprintf("badge subject %q does not match disclosed DID %q",
			badgeResult.Claims.Subject, serverDID)
		return result, nil
	}

	// Step 8: Extract trust level from verified badge (string per RFC-002 §5)
	result.TrustLevelStr = badgeResult.Claims.TrustLevel()
	result.BadgeJTI = badgeResult.Claims.JTI
	result.BadgeExpiresAt = badgeResult.Claims.ExpiresAt()

	// Badge verification succeeded - DECLARED_PRINCIPAL
	// PoP not performed, so we cannot fully trust the server controls the key
	result.State = ServerStateDeclaredPrincipal
	result.PoPRequired = true // Indicate PoP should be performed for full verification
	return result, nil
}

// VerifyPoP verifies a server's Proof of Possession response.
//
// This is called AFTER VerifyServerIdentity succeeds (returns DECLARED_PRINCIPAL).
// The PoP data comes from the MCP initialize handshake:
// - Client sent nonce in request _meta (capiscio_pop_nonce)
// - Server returned signature in response _meta (capiscio_pop_signature)
//
// Returns updated result with VERIFIED_PRINCIPAL if PoP succeeds.
func (v *ServerIdentityVerifier) VerifyPoP(
	ctx context.Context,
	result *VerifyResult,
	popRequest *pop.MCPPoPRequest,
	popResponse *pop.MCPPoPResponse,
	publicKey ed25519.PublicKey,
	maxAge time.Duration,
) (*VerifyResult, error) {
	// Must already have DECLARED_PRINCIPAL (badge verified)
	if result.State != ServerStateDeclaredPrincipal {
		return result, nil
	}

	// Check for missing PoP data
	if popRequest == nil || popResponse == nil {
		result.ErrorCode = ServerErrorCodePoPFailed
		result.ErrorDetail = "PoP request or response missing"
		// Keep DECLARED_PRINCIPAL - badge valid but PoP not performed
		return result, nil
	}

	// Verify PoP using shared primitives
	if err := pop.VerifyMCPPoPResponse(popRequest, popResponse, publicKey, maxAge); err != nil {
		result.ErrorCode = ServerErrorCodePoPFailed
		result.ErrorDetail = fmt.Sprintf("PoP verification failed: %v", err)
		// Keep DECLARED_PRINCIPAL - badge valid but PoP failed
		return result, nil
	}

	// Full verification succeeded - VERIFIED_PRINCIPAL
	result.State = ServerStateVerifiedPrincipal
	result.PoPVerified = true
	result.PoPRequired = false

	// Cache the verified session
	v.cacheSession(result)

	return result, nil
}

// VerifyWithCache checks cache first, then performs full verification if needed.
// This is the recommended entry point for verifying server identity.
func (v *ServerIdentityVerifier) VerifyWithCache(
	ctx context.Context,
	serverDID string,
	serverBadgeJWS string,
	transportOrigin string,
	popRequest *pop.MCPPoPRequest,
	popResponse *pop.MCPPoPResponse,
	publicKey ed25519.PublicKey,
	config *VerifyConfig,
) (*VerifyResult, error) {
	// Check cache first
	if cached := v.sessionCache.Get(serverDID); cached != nil {
		return &VerifyResult{
			State:          ServerStateVerifiedPrincipal,
			ServerID:       cached.SubjectDID,
			TrustLevelStr:  cached.TrustLevelStr,
			BadgeJTI:       cached.BadgeJTI,
			BadgeExpiresAt: cached.BadgeExpiresAt,
			PoPVerified:    true,
			PoPRequired:    false,
		}, nil
	}

	// Verify badge
	result, err := v.VerifyServerIdentity(ctx, serverDID, serverBadgeJWS, transportOrigin, config)
	if err != nil {
		return nil, err
	}

	// If badge verified, verify PoP
	if result.State == ServerStateDeclaredPrincipal && popRequest != nil && popResponse != nil {
		maxAge := 30 * time.Second // Default max age for PoP nonce
		if config != nil && config.PoPMaxAge > 0 {
			maxAge = config.PoPMaxAge
		}
		result, err = v.VerifyPoP(ctx, result, popRequest, popResponse, publicKey, maxAge)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// cacheSession stores a verified session
func (v *ServerIdentityVerifier) cacheSession(result *VerifyResult) {
	entry := &pop.CacheEntry{
		SubjectDID:     result.ServerID,
		TrustLevelStr:  result.TrustLevelStr,
		BadgeJTI:       result.BadgeJTI,
		BadgeExpiresAt: result.BadgeExpiresAt,
		VerifiedAt:     time.Now(),
	}
	v.sessionCache.Store(result.ServerID, entry)
}

// GetCachedSession retrieves a previously verified session
// Use this to avoid re-verifying on every request within a session
func (v *ServerIdentityVerifier) GetCachedSession(serverDID string) (*pop.CacheEntry, bool) {
	entry := v.sessionCache.Get(serverDID)
	return entry, entry != nil
}

// InvalidateSession removes a cached session (e.g., on disconnect)
func (v *ServerIdentityVerifier) InvalidateSession(serverDID string) {
	v.sessionCache.Delete(serverDID)
}

// InvalidateByTrustLevel removes all sessions below a trust level
// Use when trust requirements increase
// minLevelStr should be "0", "1", "2", "3", or "4" per RFC-002 §5
func (v *ServerIdentityVerifier) InvalidateByTrustLevel(minLevelStr string) {
	v.sessionCache.InvalidateByTrustLevel(minLevelStr)
}

// CreatePoPRequest creates a PoP request for embedding in MCP initialize _meta
// Clients should call this before initialize and include result in request
func CreatePoPRequest() (*pop.MCPPoPRequest, error) {
	return pop.NewMCPPoPRequest()
}

// CreatePoPResponse creates a PoP response for embedding in MCP initialize response _meta
// Servers should call this when receiving a PoP request and include result in response
func CreatePoPResponse(clientNonce string, privateKey ed25519.PrivateKey, keyID string) (*pop.MCPPoPResponse, error) {
	return pop.CreateMCPPoPResponse(clientNonce, privateKey, keyID)
}

// isMethodAllowed checks if a DID method is in the allowed list
func isMethodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}

// checkDIDOriginBinding verifies that a did:web DID matches the transport origin.
// This uses the already-parsed DID structure from pkg/did.
func checkDIDOriginBinding(parsedDID *did.DID, transportOrigin string) bool {
	if !parsedDID.IsWebDID() {
		return true // Non-did:web always passes
	}

	// Parse transport origin
	originURL, err := url.Parse(transportOrigin)
	if err != nil || originURL.Host == "" {
		return false
	}

	// Domain from parsed DID is already URL-decoded by pkg/did
	if originURL.Host != parsedDID.Domain {
		return false
	}

	// Check path segments if present
	// did:web:example.com:servers:bot1 -> PathSegments = ["servers", "bot1"]
	// origin path must contain /servers/bot1
	if len(parsedDID.PathSegments) > 0 {
		expectedPath := "/" + strings.Join(parsedDID.PathSegments, "/")
		if !strings.HasPrefix(originURL.Path, expectedPath) {
			return false
		}
	}

	return true
}

// ParseHTTPHeaders extracts server identity from HTTP headers (RFC-007 §6.1)
// Standard headers:
// - Capiscio-Server-DID: The server's DID
// - Capiscio-Server-Badge: The server's Trust Badge (JWS)
func ParseHTTPHeaders(headers map[string]string) *ParsedIdentity {
	return &ParsedIdentity{
		ServerDID:      headers["Capiscio-Server-DID"],
		ServerBadgeJWS: headers["Capiscio-Server-Badge"],
	}
}

// ParseJSONRPCMeta extracts server identity from JSON-RPC _meta object (RFC-007 §6.2)
// Standard fields:
// - capiscio_server_did: The server's DID
// - capiscio_server_badge: The server's Trust Badge (JWS)
// - capiscio_pop_nonce: Client's PoP challenge (in request)
// - capiscio_pop_signature: Server's PoP response (in response)
func ParseJSONRPCMeta(meta map[string]interface{}) *ParsedIdentity {
	result := &ParsedIdentity{}

	if meta == nil {
		return result
	}

	if did, ok := meta["capiscio_server_did"].(string); ok {
		result.ServerDID = did
	}
	if badge, ok := meta["capiscio_server_badge"].(string); ok {
		result.ServerBadgeJWS = badge
	}

	return result
}

// ParsePoPFromMeta extracts PoP request/response from _meta
// Returns (request, response) where request is from client and response is from server
func ParsePoPFromMeta(meta map[string]interface{}) (*pop.MCPPoPRequest, *pop.MCPPoPResponse) {
	if meta == nil {
		return nil, nil
	}
	return pop.ParseMCPPoPRequestFromMeta(meta), pop.ParseMCPPoPResponseFromMeta(meta)
}

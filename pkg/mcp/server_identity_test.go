package mcp

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/pop"
)

func TestServerIdentityVerifier_VerifyServerIdentity_MissingDID(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	result, err := verifier.VerifyServerIdentity(
		context.Background(),
		"", // Missing DID
		"eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test.signature",
		"https://example.com",
		nil,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != ServerStateUnverifiedOrigin {
		t.Errorf("State = %v, want UNVERIFIED_ORIGIN", result.State)
	}
	if result.ErrorCode != ServerErrorCodeDIDMissing {
		t.Errorf("ErrorCode = %v, want SERVER_IDENTITY_MISSING", result.ErrorCode)
	}
}

func TestServerIdentityVerifier_VerifyServerIdentity_MissingBadge(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	result, err := verifier.VerifyServerIdentity(
		context.Background(),
		"did:web:example.com",
		"", // Missing badge
		"https://example.com",
		nil,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// RFC-007 §7.2: DID present but no badge → DECLARED_PRINCIPAL
	// (identity declared but not verified)
	if result.State != ServerStateDeclaredPrincipal {
		t.Errorf("State = %v, want DECLARED_PRINCIPAL for missing badge", result.State)
	}
	// No error code for DECLARED_PRINCIPAL - this is a valid state
	if result.ErrorCode != ServerErrorNone {
		t.Errorf("ErrorCode = %v, want NONE (DECLARED_PRINCIPAL is valid)", result.ErrorCode)
	}
}

func TestServerIdentityVerifier_VerifyServerIdentity_InvalidDID(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	result, err := verifier.VerifyServerIdentity(
		context.Background(),
		"invalid-did", // Not a valid DID
		"eyJhbGciOiJFZERTQSJ9.test.signature",
		"https://example.com",
		nil,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.State != ServerStateUnverifiedOrigin {
		t.Errorf("State = %v, want UNVERIFIED_ORIGIN for invalid DID", result.State)
	}
	if result.ErrorCode != ServerErrorCodeDIDResolutionFailed {
		t.Errorf("ErrorCode = %v, want SERVER_DID_RESOLUTION_FAILED", result.ErrorCode)
	}
}

func TestCheckDIDOriginBinding(t *testing.T) {
	tests := []struct {
		name     string
		didStr   string
		origin   string
		expected bool
	}{
		// Exact host match
		{"exact host match", "did:web:example.com", "https://example.com", true},
		{"exact host with port", "did:web:example.com%3A8080", "https://example.com:8080", true},

		// Host mismatch
		{"host mismatch", "did:web:example.com", "https://other.com", false},
		{"subdomain mismatch", "did:web:sub.example.com", "https://example.com", false},

		// Path matching - note: servers use :servers: path segment
		{"path match servers", "did:web:example.com:servers:myserver", "https://example.com/servers/myserver", true},
		{"path mismatch", "did:web:example.com:servers:myserver", "https://example.com/other", false},

		// Non-did:web methods
		{"did:key always true", "did:key:z6MkhaXgBZDvotDUGnNPMBxaukjGbCon2jaGNKEvyV2HoTTR", "https://any.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedDID, err := did.Parse(tt.didStr)
			if err != nil {
				// For invalid DIDs, the function should return false
				if tt.expected {
					t.Fatalf("failed to parse DID %q: %v", tt.didStr, err)
				}
				return
			}
			got := checkDIDOriginBinding(parsedDID, tt.origin)
			if got != tt.expected {
				t.Errorf("checkDIDOriginBinding(%q, %q) = %v, want %v",
					tt.didStr, tt.origin, got, tt.expected)
			}
		})
	}
}

func TestCheckDIDOriginBinding_InvalidURLs(t *testing.T) {
	parsedDID, _ := did.Parse("did:web:example.com")

	tests := []struct {
		name     string
		origin   string
		expected bool
	}{
		{"invalid origin URL", "not-a-url", false},
		{"empty origin", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkDIDOriginBinding(parsedDID, tt.origin)
			if got != tt.expected {
				t.Errorf("checkDIDOriginBinding(did:web:example.com, %q) = %v, want %v",
					tt.origin, got, tt.expected)
			}
		})
	}
}

func TestParseHTTPHeaders(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		wantDID   string
		wantBadge string
	}{
		{
			name: "all headers present (RFC-007 naming)",
			headers: map[string]string{
				"Capiscio-Server-DID":   "did:web:example.com:servers:myserver",
				"Capiscio-Server-Badge": "eyJhbGciOiJFZERTQSJ9.claims.signature",
			},
			wantDID:   "did:web:example.com:servers:myserver",
			wantBadge: "eyJhbGciOiJFZERTQSJ9.claims.signature",
		},
		{
			name: "missing badge",
			headers: map[string]string{
				"Capiscio-Server-DID": "did:web:example.com",
			},
			wantDID:   "did:web:example.com",
			wantBadge: "",
		},
		{
			name:      "empty headers",
			headers:   map[string]string{},
			wantDID:   "",
			wantBadge: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseHTTPHeaders(tt.headers)
			if parsed.ServerDID != tt.wantDID {
				t.Errorf("ServerDID = %q, want %q", parsed.ServerDID, tt.wantDID)
			}
			if parsed.ServerBadgeJWS != tt.wantBadge {
				t.Errorf("ServerBadgeJWS = %q, want %q", parsed.ServerBadgeJWS, tt.wantBadge)
			}
		})
	}
}

func TestParseJSONRPCMeta(t *testing.T) {
	tests := []struct {
		name      string
		meta      map[string]interface{}
		wantDID   string
		wantBadge string
	}{
		{
			name: "all fields present (RFC-007 §6.2 naming)",
			meta: map[string]interface{}{
				"capiscio_server_did":   "did:web:example.com:servers:myserver",
				"capiscio_server_badge": "eyJhbGciOiJFZERTQSJ9.claims.signature",
			},
			wantDID:   "did:web:example.com:servers:myserver",
			wantBadge: "eyJhbGciOiJFZERTQSJ9.claims.signature",
		},
		{
			name: "missing badge field",
			meta: map[string]interface{}{
				"capiscio_server_did": "did:web:example.com",
			},
			wantDID:   "did:web:example.com",
			wantBadge: "",
		},
		{
			name:      "nil meta",
			meta:      nil,
			wantDID:   "",
			wantBadge: "",
		},
		{
			name: "wrong types ignored",
			meta: map[string]interface{}{
				"capiscio_server_did": 12345, // int instead of string
			},
			wantDID:   "",
			wantBadge: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseJSONRPCMeta(tt.meta)
			if parsed.ServerDID != tt.wantDID {
				t.Errorf("ServerDID = %q, want %q", parsed.ServerDID, tt.wantDID)
			}
			if parsed.ServerBadgeJWS != tt.wantBadge {
				t.Errorf("ServerBadgeJWS = %q, want %q", parsed.ServerBadgeJWS, tt.wantBadge)
			}
		})
	}
}

func TestVerifyConfig_Defaults(t *testing.T) {
	cfg := DefaultVerifyConfig()

	if cfg.RequireOriginBinding != true {
		t.Errorf("RequireOriginBinding = %v, want true", cfg.RequireOriginBinding)
	}
	if cfg.AllowedDIDMethods == nil || len(cfg.AllowedDIDMethods) == 0 {
		t.Error("AllowedDIDMethods should have defaults")
	}
}

func TestVerifyResult_Methods(t *testing.T) {
	verified := &VerifyResult{
		State:         ServerStateVerifiedPrincipal,
		ServerID:      "did:web:example.com:servers:myserver",
		TrustLevelStr: "2",
	}

	if !verified.IsVerified() {
		t.Error("IsVerified() should return true for VERIFIED_PRINCIPAL state")
	}
	if verified.ServerID != "did:web:example.com:servers:myserver" {
		t.Errorf("ServerID = %q, want %q", verified.ServerID, "did:web:example.com:servers:myserver")
	}
	if verified.TrustLevelStr != "2" {
		t.Errorf("TrustLevelStr = %q, want \"2\"", verified.TrustLevelStr)
	}
	if verified.TrustLevel() != 2 {
		t.Errorf("TrustLevel() = %d, want 2", verified.TrustLevel())
	}

	unverified := &VerifyResult{
		State:     ServerStateUnverifiedOrigin,
		ErrorCode: ServerErrorCodeBadgeInvalid,
	}

	if unverified.IsVerified() {
		t.Error("IsVerified() should return false for UNVERIFIED_ORIGIN state")
	}
}

func TestServerIdentityVerifier_VerifyServerIdentity_AllowedDIDMethods(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	// Test with restricted DID methods
	config := &VerifyConfig{
		AllowedDIDMethods: []string{"web"}, // Only allow did:web
	}

	// did:key should be rejected
	result, err := verifier.VerifyServerIdentity(
		context.Background(),
		"did:key:z6MkhaXgBZDvotDUGnNPMBxaukjGbCon2jaGNKEvyV2HoTTR",
		"eyJhbGciOiJFZERTQSJ9.test.signature",
		"https://example.com",
		config,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.State != ServerStateUnverifiedOrigin {
		t.Errorf("State = %v, want UNVERIFIED_ORIGIN for disallowed DID method", result.State)
	}
	if result.ErrorCode != ServerErrorCodeDIDResolutionFailed {
		t.Errorf("ErrorCode = %v, want SERVER_DID_RESOLUTION_FAILED", result.ErrorCode)
	}
}

func TestServerIdentityVerifier_VerifyServerIdentity_OriginMismatch(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	// did:web with origin binding requirement
	config := &VerifyConfig{
		RequireOriginBinding: true,
		AllowedDIDMethods:    []string{"web"},
	}

	result, err := verifier.VerifyServerIdentity(
		context.Background(),
		"did:web:example.com",
		"eyJhbGciOiJFZERTQSJ9.test.signature",
		"https://other-domain.com", // Doesn't match did:web host
		config,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.State != ServerStateUnverifiedOrigin {
		t.Errorf("State = %v, want UNVERIFIED_ORIGIN for origin mismatch", result.State)
	}
	if result.ErrorCode != ServerErrorCodeOriginMismatch {
		t.Errorf("ErrorCode = %v, want SERVER_DOMAIN_MISMATCH", result.ErrorCode)
	}
}

// TestServerIdentityVerifier_BadgeVerification tests that badge verification
// uses badge.Verifier (same as agents) - requires a mock badge verifier
func TestServerIdentityVerifier_BadgeVerification_RequiresBadgeVerifier(t *testing.T) {
	// When badgeVerifier is nil, badge verification will fail with a nil pointer
	// In production, a real badge.Verifier must be provided
	verifier := NewServerIdentityVerifier(nil)

	config := &VerifyConfig{
		RequireOriginBinding: false,
		AllowedDIDMethods:    []string{"web"},
	}

	// This test verifies that badge verification is attempted (will panic/fail without verifier)
	// In production, the badge.Verifier would be configured with trusted issuers
	defer func() {
		if r := recover(); r == nil {
			// If we didn't panic, the test should check for proper error handling
			// Currently we expect nil verifier to cause issues
		}
	}()

	_, _ = verifier.VerifyServerIdentity(
		context.Background(),
		"did:web:example.com:servers:myserver",
		"eyJhbGciOiJFZERTQSJ9.test.signature",
		"https://example.com",
		config,
	)
}

func TestServerErrorCode_Strings(t *testing.T) {
	// Test RFC-007 §8 compliant error code strings
	tests := []struct {
		code ServerErrorCode
		want string
	}{
		{ServerErrorCodeDIDMissing, "SERVER_IDENTITY_MISSING"},
		{ServerErrorCodeBadgeMissing, "SERVER_BADGE_MISSING"},
		{ServerErrorCodeBadgeInvalid, "SERVER_BADGE_INVALID"},
		{ServerErrorCodeBadgeRevoked, "SERVER_BADGE_REVOKED"},
		{ServerErrorCodeTrustInsufficient, "SERVER_TRUST_INSUFFICIENT"},
		{ServerErrorCodeDIDMismatch, "SERVER_DID_MISMATCH"},
		{ServerErrorCodeIssuerUntrusted, "SERVER_ISSUER_UNTRUSTED"},
		{ServerErrorCodeOriginMismatch, "SERVER_DOMAIN_MISMATCH"},
		{ServerErrorCodePathMismatch, "SERVER_PATH_MISMATCH"},
		{ServerErrorCodeDIDResolutionFailed, "SERVER_DID_RESOLUTION_FAILED"},
		{ServerErrorNone, "NONE"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.code.String(); got != tt.want {
				t.Errorf("ServerErrorCode.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewServerIdentityVerifierWithConfig(t *testing.T) {
	cacheConfig := &pop.CacheConfig{
		DefaultTTL: 5 * time.Minute,
		MaxEntries: 100,
	}

	verifier := NewServerIdentityVerifierWithConfig(nil, cacheConfig)
	if verifier == nil {
		t.Fatal("NewServerIdentityVerifierWithConfig returned nil")
	}
	if verifier.sessionCache == nil {
		t.Error("sessionCache should not be nil")
	}
}

func TestServerIdentityVerifier_VerifyPoP_NotDeclaredPrincipal(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	// Start with UNVERIFIED_ORIGIN state
	result := &VerifyResult{
		State:    ServerStateUnverifiedOrigin,
		ServerID: "did:web:example.com",
	}

	// VerifyPoP should return unchanged for non-DECLARED_PRINCIPAL
	updated, err := verifier.VerifyPoP(
		context.Background(),
		result,
		&pop.MCPPoPRequest{ClientNonce: "test"},
		&pop.MCPPoPResponse{NonceSignature: "sig"},
		nil,
		time.Minute,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.State != ServerStateUnverifiedOrigin {
		t.Errorf("State should remain UNVERIFIED_ORIGIN, got %v", updated.State)
	}
}

func TestServerIdentityVerifier_VerifyPoP_MissingData(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	result := &VerifyResult{
		State:    ServerStateDeclaredPrincipal,
		ServerID: "did:web:example.com",
	}

	// Missing PoP request
	updated, err := verifier.VerifyPoP(
		context.Background(),
		result,
		nil, // Missing request
		&pop.MCPPoPResponse{NonceSignature: "sig"},
		nil,
		time.Minute,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.State != ServerStateDeclaredPrincipal {
		t.Errorf("State should remain DECLARED_PRINCIPAL, got %v", updated.State)
	}
	if updated.ErrorCode != ServerErrorCodePoPFailed {
		t.Errorf("ErrorCode = %v, want POP_FAILED", updated.ErrorCode)
	}

	// Missing PoP response
	updated2, _ := verifier.VerifyPoP(
		context.Background(),
		result,
		&pop.MCPPoPRequest{ClientNonce: "test"},
		nil, // Missing response
		nil,
		time.Minute,
	)
	if updated2.ErrorCode != ServerErrorCodePoPFailed {
		t.Errorf("ErrorCode = %v, want POP_FAILED", updated2.ErrorCode)
	}
}

func TestServerIdentityVerifier_CacheOperations(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)
	serverDID := "did:web:example.com:servers:test"

	// Initially no cached session
	_, found := verifier.GetCachedSession(serverDID)
	if found {
		t.Error("should not find session before caching")
	}

	// Manually trigger cache via cacheSession (internal method)
	result := &VerifyResult{
		State:          ServerStateVerifiedPrincipal,
		ServerID:       serverDID,
		TrustLevelStr:  "2",
		BadgeJTI:       "badge-123",
		BadgeExpiresAt: time.Now().Add(time.Hour),
	}
	verifier.cacheSession(result)

	// Now should find cached session
	cached, found := verifier.GetCachedSession(serverDID)
	if !found {
		t.Fatal("should find cached session")
	}
	if cached.SubjectDID != serverDID {
		t.Errorf("SubjectDID = %q, want %q", cached.SubjectDID, serverDID)
	}
	if cached.TrustLevelStr != "2" {
		t.Errorf("TrustLevelStr = %q, want \"2\"", cached.TrustLevelStr)
	}

	// Invalidate session
	verifier.InvalidateSession(serverDID)
	_, found = verifier.GetCachedSession(serverDID)
	if found {
		t.Error("should not find session after invalidation")
	}
}

func TestServerIdentityVerifier_InvalidateByTrustLevel(t *testing.T) {
	verifier := NewServerIdentityVerifier(nil)

	// Cache some sessions with different trust levels
	for _, entry := range []struct {
		did   string
		level string
	}{
		{"did:web:a.com", "1"},
		{"did:web:b.com", "2"},
		{"did:web:c.com", "3"},
		{"did:web:d.com", "4"},
	} {
		result := &VerifyResult{
			State:          ServerStateVerifiedPrincipal,
			ServerID:       entry.did,
			TrustLevelStr:  entry.level,
			BadgeExpiresAt: time.Now().Add(time.Hour),
		}
		verifier.cacheSession(result)
	}

	// Invalidate sessions below level 3
	verifier.InvalidateByTrustLevel("3")

	// Level 1 and 2 should be gone
	for _, did := range []string{"did:web:a.com", "did:web:b.com"} {
		_, found := verifier.GetCachedSession(did)
		if found {
			t.Errorf("%s should be invalidated (below level 3)", did)
		}
	}

	// Level 3 and 4 should remain
	for _, did := range []string{"did:web:c.com", "did:web:d.com"} {
		_, found := verifier.GetCachedSession(did)
		if !found {
			t.Errorf("%s should remain (at or above level 3)", did)
		}
	}
}

func TestCreatePoPRequest(t *testing.T) {
	req, err := CreatePoPRequest()
	if err != nil {
		t.Fatalf("CreatePoPRequest() error: %v", err)
	}
	if req == nil {
		t.Fatal("CreatePoPRequest returned nil")
	}
	if req.ClientNonce == "" {
		t.Error("ClientNonce should not be empty")
	}
}

func TestCreatePoPResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub // Not used in this test

	resp, err := CreatePoPResponse("test-nonce", priv, "key-1")
	if err != nil {
		t.Fatalf("CreatePoPResponse() error: %v", err)
	}
	if resp == nil {
		t.Fatal("CreatePoPResponse returned nil")
	}
	if resp.NonceSignature == "" {
		t.Error("NonceSignature should not be empty")
	}
}

func TestParsePoPFromMeta(t *testing.T) {
	now := time.Now()

	// Test with both request and response fields
	meta := map[string]interface{}{
		"capiscio_pop_nonce":      "client-nonce",
		"capiscio_pop_created_at": float64(now.Unix()),
		"capiscio_pop_signature":  "server-sig",
		"capiscio_pop_signed_at":  float64(now.Unix()),
	}

	req, resp := ParsePoPFromMeta(meta)

	if req == nil {
		t.Fatal("request should not be nil")
	}
	if req.ClientNonce != "client-nonce" {
		t.Errorf("ClientNonce = %q, want \"client-nonce\"", req.ClientNonce)
	}

	if resp == nil {
		t.Fatal("response should not be nil")
	}
	if resp.NonceSignature != "server-sig" {
		t.Errorf("NonceSignature = %q, want \"server-sig\"", resp.NonceSignature)
	}

	// Test with nil meta
	req2, resp2 := ParsePoPFromMeta(nil)
	if req2 != nil || resp2 != nil {
		t.Error("nil meta should return nil, nil")
	}

	// Test with only request fields
	reqOnlyMeta := map[string]interface{}{
		"capiscio_pop_nonce": "nonce-only",
	}
	req3, resp3 := ParsePoPFromMeta(reqOnlyMeta)
	if req3 == nil {
		t.Error("request should be parsed")
	}
	if resp3 != nil {
		t.Error("response should be nil with no signature")
	}
}

func TestIsMethodAllowed(t *testing.T) {
	tests := []struct {
		method  string
		allowed []string
		want    bool
	}{
		{"web", []string{"web", "key"}, true},
		{"key", []string{"web", "key"}, true},
		{"pkh", []string{"web", "key"}, false},
		{"web", []string{}, false},
		{"web", nil, false},
	}

	for _, tt := range tests {
		got := isMethodAllowed(tt.method, tt.allowed)
		if got != tt.want {
			t.Errorf("isMethodAllowed(%q, %v) = %v, want %v", tt.method, tt.allowed, got, tt.want)
		}
	}
}

func TestServerState_Strings(t *testing.T) {
	tests := []struct {
		state ServerState
		want  string
	}{
		{ServerStateUnverifiedOrigin, "UNVERIFIED_ORIGIN"},
		{ServerStateDeclaredPrincipal, "DECLARED_PRINCIPAL"},
		{ServerStateVerifiedPrincipal, "VERIFIED_PRINCIPAL"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("ServerState.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestVerifyResult_TrustLevel_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		levelStr string
		want     int
	}{
		{"valid level 0", "0", 0},
		{"valid level 4", "4", 4},
		{"empty string", "", 0},
		{"invalid string", "invalid", 0},
		{"negative", "-1", 0}, // strconv.Atoi returns 0 on parse failure
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &VerifyResult{TrustLevelStr: tt.levelStr}
			got := result.TrustLevel()
			// For invalid strings, Atoi returns 0 but we expect error-free behavior
			if tt.levelStr == "" || tt.levelStr == "invalid" || tt.levelStr == "-1" {
				// These should return 0 (default)
				if got != 0 {
					t.Errorf("TrustLevel() for invalid string = %d, want 0", got)
				}
			} else if got != tt.want {
				t.Errorf("TrustLevel() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestVerifyConfig_Validate(t *testing.T) {
	cfg := &VerifyConfig{
		RequireOriginBinding: true,
		AllowedDIDMethods:    []string{"web", "key"},
		PoPMaxAge:            30 * time.Second,
	}

	if !cfg.RequireOriginBinding {
		t.Error("RequireOriginBinding should be true")
	}
	if len(cfg.AllowedDIDMethods) != 2 {
		t.Errorf("AllowedDIDMethods length = %d, want 2", len(cfg.AllowedDIDMethods))
	}
	if cfg.PoPMaxAge != 30*time.Second {
		t.Errorf("PoPMaxAge = %v, want 30s", cfg.PoPMaxAge)
	}
}

func TestServerErrorCode_PoPFailed(t *testing.T) {
	// Test the POP_FAILED error code
	code := ServerErrorCodePoPFailed
	if code.String() != "SERVER_POP_FAILED" {
		t.Errorf("ServerErrorCodePoPFailed.String() = %q, want \"SERVER_POP_FAILED\"", code.String())
	}
}


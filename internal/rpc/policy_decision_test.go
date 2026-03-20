package rpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// mockPDP sets up an httptest server returning a fixed PDP response.
func mockPDP(t *testing.T, decision, decisionID, reason string, ttl *int, obligations []pip.Obligation) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := pip.DecisionResponse{
			Decision:    decision,
			DecisionID:  decisionID,
			Reason:      reason,
			TTL:         ttl,
			Obligations: obligations,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// mockPDPError sets up an httptest server that returns an error status.
func mockPDPError(t *testing.T, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "pdp error", statusCode)
	}))
}

// mockPDPSlow sets up an httptest server that takes longer than timeout.
func mockPDPSlow(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		resp := pip.DecisionResponse{Decision: "ALLOW", DecisionID: "slow-1"}
		json.NewEncoder(w).Encode(resp)
	}))
}

func basicRequest(pdpEndpoint string) *pb.PolicyDecisionRequest {
	return &pb.PolicyDecisionRequest{
		Subject: &pb.PolicySubject{
			Did:        "did:web:agent.example.com",
			BadgeJti:   "badge-123",
			Ial:        "ial-2",
			TrustLevel: "2",
			BadgeExp:   time.Now().Add(1 * time.Hour).Unix(),
		},
		Action: &pb.PolicyAction{
			Operation: "read_file",
		},
		Resource: &pb.PolicyResource{
			Identifier: "/data/report.csv",
		},
		Config: &pb.PolicyConfig{
			PdpEndpoint:    pdpEndpoint,
			PdpTimeoutMs:   500,
			EnforcementMode: "EM-GUARD",
			PepId:          "test-pep",
		},
	}
}

func newTestService(t *testing.T) *MCPService {
	t.Helper()
	svc, err := NewMCPServiceWithConfig(MCPServiceConfig{})
	require.NoError(t, err, "newTestService: failed to create MCPService")
	return svc
}

func TestEvaluatePolicyDecision_NoPDP(t *testing.T) {
	svc := newTestService(t)

	req := &pb.PolicyDecisionRequest{
		Subject: &pb.PolicySubject{Did: "did:web:test"},
		Action:  &pb.PolicyAction{Operation: "read_file"},
		Resource: &pb.PolicyResource{Identifier: "/test"},
		Config:  &pb.PolicyConfig{}, // No PDP endpoint
	}

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.Equal(t, "no-pdp-configured", resp.DecisionId)
	assert.Equal(t, "EM-OBSERVE", resp.EnforcementMode)
	assert.NotEmpty(t, resp.TxnId)
}

func TestEvaluatePolicyDecision_PDPAllow(t *testing.T) {
	pdp := mockPDP(t, "ALLOW", "dec-allow-1", "", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.Equal(t, "dec-allow-1", resp.DecisionId)
	assert.Equal(t, "EM-GUARD", resp.EnforcementMode)
	assert.False(t, resp.CacheHit)
	assert.False(t, resp.BreakglassOverride)
	assert.NotEmpty(t, resp.TxnId)
	assert.GreaterOrEqual(t, resp.PdpLatencyMs, int64(0))
}

func TestEvaluatePolicyDecision_PDPDeny_Guard(t *testing.T) {
	pdp := mockPDP(t, "DENY", "dec-deny-1", "insufficient trust", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.EnforcementMode = "EM-GUARD"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "dec-deny-1", resp.DecisionId)
	assert.Equal(t, "insufficient trust", resp.Reason)
}

func TestEvaluatePolicyDecision_PDPDeny_Observe(t *testing.T) {
	pdp := mockPDP(t, "DENY", "dec-deny-2", "denied by policy", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.EnforcementMode = "EM-OBSERVE"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionObserve, resp.Decision, "EM-OBSERVE should convert DENY to ALLOW_OBSERVE")
	assert.Equal(t, "dec-deny-2", resp.DecisionId)
}

func TestEvaluatePolicyDecision_PDPUnavailable_FailClosed(t *testing.T) {
	pdp := mockPDPError(t, http.StatusInternalServerError)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.EnforcementMode = "EM-STRICT"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err, "PDP unavailability must not produce an RPC error")
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "pdp-unavailable", resp.DecisionId)
	assert.Equal(t, "pdp_unavailable", resp.ErrorCode)
}

func TestEvaluatePolicyDecision_PDPUnavailable_Observe(t *testing.T) {
	pdp := mockPDPError(t, http.StatusInternalServerError)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.EnforcementMode = "EM-OBSERVE"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err, "PDP unavailability must not produce an RPC error")
	assert.Equal(t, pip.DecisionObserve, resp.Decision, "EM-OBSERVE + PDP unavailable → ALLOW_OBSERVE")
	assert.Equal(t, "pdp_unavailable", resp.ErrorCode)
	assert.NotEmpty(t, resp.Reason)
}

func TestEvaluatePolicyDecision_PDPTimeout(t *testing.T) {
	pdp := mockPDPSlow(t, 2*time.Second)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.PdpTimeoutMs = 50 // 50ms timeout, PDP takes 2s
	req.Config.EnforcementMode = "EM-DELEGATE"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err, "PDP timeout must not produce an RPC error")
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "pdp_timeout", resp.ErrorCode)
}

func TestEvaluatePolicyDecision_InvalidEnforcementMode(t *testing.T) {
	svc := newTestService(t)
	req := basicRequest("http://localhost:9999")
	req.Config.EnforcementMode = "INVALID-MODE"

	_, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.Error(t, err, "Invalid enforcement mode should return an RPC error")
	assert.Contains(t, err.Error(), "invalid enforcement_mode")
}

func TestEvaluatePolicyDecision_DefaultEnforcementMode(t *testing.T) {
	svc := newTestService(t)

	req := &pb.PolicyDecisionRequest{
		Subject:  &pb.PolicySubject{Did: "did:web:test"},
		Action:   &pb.PolicyAction{Operation: "test"},
		Resource: &pb.PolicyResource{Identifier: "/test"},
		Config:   &pb.PolicyConfig{}, // No enforcement mode, no PDP
	}

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "EM-OBSERVE", resp.EnforcementMode)
}

func TestEvaluatePolicyDecision_NilConfig(t *testing.T) {
	svc := newTestService(t)

	req := &pb.PolicyDecisionRequest{
		Subject:  &pb.PolicySubject{Did: "did:web:test"},
		Action:   &pb.PolicyAction{Operation: "test"},
		Resource: &pb.PolicyResource{Identifier: "/test"},
		// No config at all
	}

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.Equal(t, "no-pdp-configured", resp.DecisionId)
}

func TestEvaluatePolicyDecision_WithObligations(t *testing.T) {
	obligations := []pip.Obligation{
		{Type: "rate_limit", Params: json.RawMessage(`{"max_rps": 10}`)},
		{Type: "audit_log", Params: json.RawMessage(`{"level": "info"}`)},
	}
	pdp := mockPDP(t, "ALLOW", "dec-obl-1", "", nil, obligations)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	require.Len(t, resp.Obligations, 2)
	assert.Equal(t, "rate_limit", resp.Obligations[0].Type)
	assert.JSONEq(t, `{"max_rps": 10}`, resp.Obligations[0].ParamsJson)
	assert.Equal(t, "audit_log", resp.Obligations[1].Type)
}

func TestEvaluatePolicyDecision_CacheHit(t *testing.T) {
	callCount := 0
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := pip.DecisionResponse{
			Decision:   "ALLOW",
			DecisionID: fmt.Sprintf("dec-cache-%d", callCount),
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)

	// First call: cache miss
	resp1, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp1.Decision)
	assert.False(t, resp1.CacheHit)
	assert.Equal(t, 1, callCount)

	// Second call: cache hit (same subject/action/resource)
	resp2, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp2.Decision)
	assert.True(t, resp2.CacheHit)
	assert.Equal(t, 1, callCount, "PDP should not be called again on cache hit")
}

func TestEvaluatePolicyDecision_CachedDeny_Observe(t *testing.T) {
	pdp := mockPDP(t, "DENY", "dec-deny-cached", "denied", nil, nil)
	defer pdp.Close()

	// Create service with DENY caching enabled
	svc := newTestService(t)
	svc.decisionCache = pip.NewInMemoryCache(pip.WithCacheDeny(true))

	req := basicRequest(pdp.URL)
	req.Config.EnforcementMode = "EM-OBSERVE"

	// First call — caches the DENY under EM-OBSERVE key
	resp1, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionObserve, resp1.Decision)

	// Second call with same EM-OBSERVE — cached DENY returned as ALLOW_OBSERVE
	resp2, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionObserve, resp2.Decision)
	assert.True(t, resp2.CacheHit)
}

func TestEvaluatePolicyDecision_InvalidPDPResponse(t *testing.T) {
	// PDP returns invalid decision
	pdp := mockPDP(t, "MAYBE", "dec-invalid", "", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.EnforcementMode = "EM-DELEGATE"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err, "Invalid PDP response must not produce an RPC error")
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "pdp_invalid_response", resp.ErrorCode)
}

func TestEvaluatePolicyDecision_EmptyDecisionID(t *testing.T) {
	// PDP returns empty decision_id (non-compliant)
	pdp := mockPDP(t, "ALLOW", "", "", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionDeny, resp.Decision)
	assert.Equal(t, "pdp_invalid_response", resp.ErrorCode)
}

func TestEvaluatePolicyDecision_WithTTL(t *testing.T) {
	ttl := 300
	pdp := mockPDP(t, "ALLOW", "dec-ttl-1", "", &ttl, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, int32(300), resp.Ttl)
}

func TestEvaluatePolicyDecision_ZeroTimeout(t *testing.T) {
	pdp := mockPDP(t, "ALLOW", "dec-timeout-0", "", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.PdpTimeoutMs = 0 // Should default to 500ms, not hang

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
}

func TestEvaluatePolicyDecision_AllEnforcementModes(t *testing.T) {
	pdp := mockPDP(t, "DENY", "dec-em-test", "policy denied", nil, nil)
	defer pdp.Close()

	tests := []struct {
		mode     string
		expected string
	}{
		{"EM-OBSERVE", pip.DecisionObserve},
		{"EM-GUARD", pip.DecisionDeny},
		{"EM-DELEGATE", pip.DecisionDeny},
		{"EM-STRICT", pip.DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			svc := newTestService(t)
			req := basicRequest(pdp.URL)
			req.Config.EnforcementMode = tt.mode

			resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, resp.Decision, "mode=%s", tt.mode)
		})
	}
}

func TestEvaluatePolicyDecision_TxnIDIsUUID(t *testing.T) {
	svc := newTestService(t)

	req := &pb.PolicyDecisionRequest{
		Subject:  &pb.PolicySubject{Did: "did:web:test"},
		Action:   &pb.PolicyAction{Operation: "test"},
		Resource: &pb.PolicyResource{Identifier: "/test"},
	}

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Len(t, resp.TxnId, 36, "TxnID should be a UUID (36 chars with hyphens)")
	assert.Contains(t, resp.TxnId, "-")
}

func TestEvaluatePolicyDecision_PDPSeesCorrectRequest(t *testing.T) {
	var receivedReq pip.DecisionRequest
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedReq)
		resp := pip.DecisionResponse{Decision: "ALLOW", DecisionID: "dec-verify"}
		json.NewEncoder(w).Encode(resp)
	}))
	defer pdp.Close()

	svc := newTestService(t)
	req := &pb.PolicyDecisionRequest{
		Subject: &pb.PolicySubject{
			Did:        "did:web:agent.test",
			BadgeJti:   "jti-456",
			Ial:        "ial-2",
			TrustLevel: "3",
		},
		Action: &pb.PolicyAction{
			Operation: "write_file",
		},
		Resource: &pb.PolicyResource{
			Identifier: "/data/output.json",
		},
		Config: &pb.PolicyConfig{
			PdpEndpoint:     pdp.URL,
			PdpTimeoutMs:    500,
			EnforcementMode: "EM-DELEGATE",
			PepId:           "pep-test-1",
			Workspace:       "ws-prod",
		},
	}

	_, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)

	// Verify PIP request structure
	assert.Equal(t, pip.PIPVersion, receivedReq.PIPVersion)
	assert.Equal(t, "did:web:agent.test", receivedReq.Subject.DID)
	assert.Equal(t, "jti-456", receivedReq.Subject.BadgeJTI)
	assert.Equal(t, "ial-2", receivedReq.Subject.IAL)
	assert.Equal(t, "3", receivedReq.Subject.TrustLevel)
	assert.Equal(t, "write_file", receivedReq.Action.Operation)
	assert.Equal(t, "/data/output.json", receivedReq.Resource.Identifier)
	assert.Equal(t, "EM-DELEGATE", receivedReq.Context.EnforcementMode)
	assert.NotEmpty(t, receivedReq.Context.TxnID)
	assert.Equal(t, "pep-test-1", *receivedReq.Environment.PEPID)
	assert.Equal(t, "ws-prod", *receivedReq.Environment.Workspace)
}

func TestObligationsToProto(t *testing.T) {
	t.Run("nil obligations", func(t *testing.T) {
		assert.Nil(t, obligationsToProto(nil))
	})

	t.Run("empty obligations", func(t *testing.T) {
		assert.Nil(t, obligationsToProto([]pip.Obligation{}))
	})

	t.Run("with obligations", func(t *testing.T) {
		obs := []pip.Obligation{
			{Type: "rate_limit", Params: json.RawMessage(`{"max": 100}`)},
		}
		result := obligationsToProto(obs)
		require.Len(t, result, 1)
		assert.Equal(t, "rate_limit", result[0].Type)
		assert.Equal(t, `{"max": 100}`, result[0].ParamsJson)
	})
}

// ---------------------------------------------------------------------------
// Break-glass helpers and tests
// ---------------------------------------------------------------------------

// signBreakGlassJWS creates a compact JWS signed with the given Ed25519 private key.
func signBreakGlassJWS(t *testing.T, privKey ed25519.PrivateKey, token *pip.BreakGlassToken) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privKey}, nil)
	require.NoError(t, err, "create JWS signer")

	payload, err := json.Marshal(token)
	require.NoError(t, err, "marshal break-glass token")

	jws, err := signer.Sign(payload)
	require.NoError(t, err, "sign break-glass token")

	compact, err := jws.CompactSerialize()
	require.NoError(t, err, "serialize JWS")
	return compact
}

func generateBGKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "generate ed25519 key pair")
	return pub, priv
}

func validBreakGlassToken() *pip.BreakGlassToken {
	return &pip.BreakGlassToken{
		JTI:    "bg-test-001",
		IAT:    time.Now().Add(-1 * time.Minute).Unix(),
		EXP:    time.Now().Add(10 * time.Minute).Unix(),
		ISS:    "admin@example.com",
		SUB:    "oncall-operator",
		Reason: "emergency database maintenance",
		Scope:  pip.BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
	}
}

func TestEvaluatePolicyDecision_BreakGlass_Valid(t *testing.T) {
	pubKey, privKey := generateBGKeyPair(t)

	pdp := mockPDP(t, "DENY", "dec-deny-bg", "denied by policy", nil, nil)
	defer pdp.Close()

	bgToken := validBreakGlassToken()
	jws := signBreakGlassJWS(t, privKey, bgToken)

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.BreakglassPublicKey = []byte(pubKey)
	req.BreakglassToken = jws

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, pip.DecisionAllow, resp.Decision)
	assert.True(t, resp.BreakglassOverride)
	assert.Equal(t, "bg-test-001", resp.BreakglassJti)
	assert.Equal(t, "emergency database maintenance", resp.Reason)
	assert.Contains(t, resp.DecisionId, "breakglass:")
}

func TestEvaluatePolicyDecision_BreakGlass_WrongKey(t *testing.T) {
	_, privKey := generateBGKeyPair(t)
	wrongPub, _ := generateBGKeyPair(t) // different key pair

	pdp := mockPDP(t, "ALLOW", "dec-allow-bg", "", nil, nil)
	defer pdp.Close()

	bgToken := validBreakGlassToken()
	jws := signBreakGlassJWS(t, privKey, bgToken)

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.BreakglassPublicKey = []byte(wrongPub) // wrong key
	req.BreakglassToken = jws

	// Break-glass fails silently, falls through to normal PDP path
	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.BreakglassOverride)
	assert.Equal(t, pip.DecisionAllow, resp.Decision) // PDP allows
	assert.Equal(t, "dec-allow-bg", resp.DecisionId)  // from PDP, not break-glass
}

func TestEvaluatePolicyDecision_BreakGlass_NoKeyConfigured(t *testing.T) {
	pdp := mockPDP(t, "ALLOW", "dec-allow-nokey", "", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	// No BreakglassPublicKey configured
	req.BreakglassToken = "some-token"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.BreakglassOverride)
	assert.Equal(t, "dec-allow-nokey", resp.DecisionId) // fell through to PDP
}

func TestEvaluatePolicyDecision_BreakGlass_ScopeMismatch(t *testing.T) {
	pubKey, privKey := generateBGKeyPair(t)

	pdp := mockPDP(t, "DENY", "dec-deny-scope", "denied", nil, nil)
	defer pdp.Close()

	bgToken := validBreakGlassToken()
	bgToken.Scope = pip.BreakGlassScope{
		Methods: []string{"*"},
		Routes:  []string{"/admin/*"}, // does NOT cover "read_file"
	}
	jws := signBreakGlassJWS(t, privKey, bgToken)

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.BreakglassPublicKey = []byte(pubKey)
	req.BreakglassToken = jws

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.BreakglassOverride)
	assert.Equal(t, pip.DecisionDeny, resp.Decision) // PDP DENY, scope didn't match
}

func TestEvaluatePolicyDecision_BreakGlass_BadKeySize(t *testing.T) {
	pdp := mockPDP(t, "ALLOW", "dec-allow-badkey", "", nil, nil)
	defer pdp.Close()

	svc := newTestService(t)
	req := basicRequest(pdp.URL)
	req.Config.BreakglassPublicKey = []byte("too-short") // wrong size
	req.BreakglassToken = "some-token"

	resp, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, resp.BreakglassOverride)
	assert.Equal(t, "dec-allow-badkey", resp.DecisionId) // fell through to PDP
}

func TestEvaluatePolicyDecision_InvalidEnforcementMode_NoPDP(t *testing.T) {
	svc := newTestService(t)
	req := &pb.PolicyDecisionRequest{
		Subject:  &pb.PolicySubject{Did: "did:web:test"},
		Action:   &pb.PolicyAction{Operation: "test"},
		Resource: &pb.PolicyResource{Identifier: "/test"},
		Config:   &pb.PolicyConfig{EnforcementMode: "INVALID"},
	}

	_, err := svc.EvaluatePolicyDecision(context.Background(), req)
	require.Error(t, err, "Invalid enforcement mode should error even without PDP")
	assert.Contains(t, err.Error(), "invalid enforcement_mode")
}

func TestClassifyPDPError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"context deadline", context.DeadlineExceeded, "pdp_timeout"},
		{"context canceled", context.Canceled, "pdp_unavailable"},
		{"invalid PDP response", &invalidPDPResponseError{decision: "MAYBE"}, "pdp_invalid_response"},
		{"invalid decision message", fmt.Errorf("pip: pdp returned invalid decision %q", "MAYBE"), "pdp_invalid_response"},
		{"empty decision_id message", fmt.Errorf("pip: pdp returned empty decision_id"), "pdp_invalid_response"},
		{"unmarshal error", fmt.Errorf("pip: unmarshal pdp response: invalid json"), "pdp_invalid_response"},
		{"generic network error", fmt.Errorf("connection refused"), "pdp_unavailable"},
		{"wrapped timeout", fmt.Errorf("pip: pdp request failed: %w", context.DeadlineExceeded), "pdp_timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, classifyPDPError(tt.err))
		})
	}
}

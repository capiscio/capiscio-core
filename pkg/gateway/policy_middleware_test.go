package gateway_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/capiscio/capiscio-core/v2/pkg/gateway"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
)

// --- Test helpers ---

type mockRegistry struct {
	key crypto.PublicKey
}

func (m *mockRegistry) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return m.key, nil
}

func (m *mockRegistry) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (m *mockRegistry) GetBadgeStatus(_ context.Context, _ string, jti string) (*registry.BadgeStatus, error) {
	return &registry.BadgeStatus{JTI: jti, Revoked: false}, nil
}

func (m *mockRegistry) GetAgentStatus(_ context.Context, _ string, agentID string) (*registry.AgentStatus, error) {
	return &registry.AgentStatus{ID: agentID, Status: registry.AgentStatusActive}, nil
}

func (m *mockRegistry) SyncRevocations(_ context.Context, _ string, _ time.Time) ([]registry.Revocation, error) {
	return nil, nil
}

type mockPDP struct {
	resp *pip.DecisionResponse
	err  error
	mu   sync.Mutex
	reqs []*pip.DecisionRequest
}

func (m *mockPDP) Evaluate(_ context.Context, req *pip.DecisionRequest) (*pip.DecisionResponse, error) {
	m.mu.Lock()
	m.reqs = append(m.reqs, req)
	m.mu.Unlock()
	return m.resp, m.err
}

func (m *mockPDP) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reqs)
}

func (m *mockPDP) lastRequest() *pip.DecisionRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.reqs) == 0 {
		return nil
	}
	return m.reqs[len(m.reqs)-1]
}

type mockObligationHandler struct {
	supported string
	err       error
}

func (h *mockObligationHandler) Handle(_ context.Context, _ pip.Obligation) error {
	return h.err
}

func (h *mockObligationHandler) Supports(t string) bool {
	return t == h.supported
}

// testSetup creates a common test environment.
type testSetup struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	verifier *badge.Verifier
	token    string
	claims   *badge.Claims
}

func newTestSetup(t *testing.T) *testSetup {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &mockRegistry{key: pub}
	verifier := badge.NewVerifier(reg)

	claims := &badge.Claims{
		JTI:      "test-jti-policy",
		Issuer:   "did:web:test.capisc.io",
		Subject:  "did:web:test.capisc.io:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		IAL:      "IAL-1",
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "2",
			},
		},
	}
	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	return &testSetup{
		pub:      pub,
		priv:     priv,
		verifier: verifier,
		token:    token,
		claims:   claims,
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func signBreakGlassToken(t *testing.T, priv ed25519.PrivateKey, token *pip.BreakGlassToken) string {
	t.Helper()
	payload, err := json.Marshal(token)
	require.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, nil)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	compact, err := jws.CompactSerialize()
	require.NoError(t, err)

	return compact
}

// --- Tests ---

func TestPolicyMiddleware_BadgeOnlyMode(t *testing.T) {
	ts := newTestSetup(t)

	config := gateway.PEPConfig{
		// PDPClient nil = badge-only mode
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	t.Run("valid badge passes through", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		rr := httptest.NewRecorder()

		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "OK", rr.Body.String())
	})

	t.Run("missing badge returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		rr := httptest.NewRecorder()

		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("invalid badge returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", "invalid.token")
		rr := httptest.NewRecorder()

		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestPolicyMiddleware_PDPAllow(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "test-decision-001",
		},
	}

	var capturedEvent gateway.PolicyEvent
	callback := func(event gateway.PolicyEvent, req *pip.DecisionRequest) {
		capturedEvent = event
	}

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMDelegate,
		PEPID:           "test-pep",
		Workspace:       "test-workspace",
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

	req := httptest.NewRequest("GET", "/v1/agents/abc", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, 1, pdp.callCount())

	// Verify PIP request
	pipReq := pdp.lastRequest()
	assert.Equal(t, pip.PIPVersion, pipReq.PIPVersion)
	assert.Equal(t, ts.claims.Subject, pipReq.Subject.DID)
	assert.Equal(t, ts.claims.JTI, pipReq.Subject.BadgeJTI)
	assert.Equal(t, "IAL-1", pipReq.Subject.IAL)
	assert.Equal(t, "2", pipReq.Subject.TrustLevel)
	assert.Equal(t, "GET /v1/agents/abc", pipReq.Action.Operation)
	assert.Equal(t, "/v1/agents/abc", pipReq.Resource.Identifier)
	assert.Equal(t, pip.EMDelegate.String(), pipReq.Context.EnforcementMode)
	assert.Nil(t, pipReq.Action.CapabilityClass)
	assert.Nil(t, pipReq.Context.EnvelopeID)
	assert.Nil(t, pipReq.Context.Constraints)
	assert.NotEmpty(t, pipReq.Context.TxnID)

	// Verify event callback
	assert.Equal(t, pip.DecisionAllow, capturedEvent.Decision)
	assert.Equal(t, "test-decision-001", capturedEvent.DecisionID)
	assert.False(t, capturedEvent.Override)
	assert.False(t, capturedEvent.CacheHit)
}

func TestPolicyMiddleware_PDPDeny(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionDeny,
			DecisionID: "deny-001",
			Reason:     "insufficient permissions",
		},
	}

	tests := []struct {
		name           string
		mode           pip.EnforcementMode
		expectedStatus int
		expectedDecision string
	}{
		{
			name:             "EM-OBSERVE allows through on DENY",
			mode:             pip.EMObserve,
			expectedStatus:   http.StatusOK,
			expectedDecision: pip.DecisionObserve,
		},
		{
			name:             "EM-GUARD blocks on DENY",
			mode:             pip.EMGuard,
			expectedStatus:   http.StatusForbidden,
			expectedDecision: pip.DecisionDeny,
		},
		{
			name:             "EM-DELEGATE blocks on DENY",
			mode:             pip.EMDelegate,
			expectedStatus:   http.StatusForbidden,
			expectedDecision: pip.DecisionDeny,
		},
		{
			name:             "EM-STRICT blocks on DENY",
			mode:             pip.EMStrict,
			expectedStatus:   http.StatusForbidden,
			expectedDecision: pip.DecisionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedEvent gateway.PolicyEvent
			callback := func(event gateway.PolicyEvent, req *pip.DecisionRequest) {
				capturedEvent = event
			}

			config := gateway.PEPConfig{
				PDPClient:       pdp,
				EnforcementMode: tc.mode,
			}

			mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

			req := httptest.NewRequest("GET", "/v1/agents", nil)
			req.Header.Set("X-Capiscio-Badge", ts.token)
			rr := httptest.NewRecorder()

			mw.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedDecision, capturedEvent.Decision)
		})
	}
}

func TestPolicyMiddleware_PDPUnavailable(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		err: fmt.Errorf("connection refused"),
	}

	tests := []struct {
		name             string
		mode             pip.EnforcementMode
		expectedStatus   int
		expectedDecision string
		expectedError    string
	}{
		{
			name:             "EM-OBSERVE allows on PDP unavailable",
			mode:             pip.EMObserve,
			expectedStatus:   http.StatusOK,
			expectedDecision: pip.DecisionObserve,
			expectedError:    pip.ErrorCodePDPUnavailable,
		},
		{
			name:             "EM-GUARD denies on PDP unavailable (fail-closed)",
			mode:             pip.EMGuard,
			expectedStatus:   http.StatusForbidden,
			expectedDecision: pip.DecisionDeny,
			expectedError:    pip.ErrorCodePDPUnavailable,
		},
		{
			name:             "EM-DELEGATE denies on PDP unavailable (fail-closed)",
			mode:             pip.EMDelegate,
			expectedStatus:   http.StatusForbidden,
			expectedDecision: pip.DecisionDeny,
			expectedError:    pip.ErrorCodePDPUnavailable,
		},
		{
			name:             "EM-STRICT denies on PDP unavailable (fail-closed)",
			mode:             pip.EMStrict,
			expectedStatus:   http.StatusForbidden,
			expectedDecision: pip.DecisionDeny,
			expectedError:    pip.ErrorCodePDPUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedEvent gateway.PolicyEvent
			callback := func(event gateway.PolicyEvent, req *pip.DecisionRequest) {
				capturedEvent = event
			}

			config := gateway.PEPConfig{
				PDPClient:       pdp,
				EnforcementMode: tc.mode,
			}

			mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

			req := httptest.NewRequest("GET", "/v1/agents", nil)
			req.Header.Set("X-Capiscio-Badge", ts.token)
			rr := httptest.NewRecorder()

			mw.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Equal(t, tc.expectedDecision, capturedEvent.Decision)
			assert.Equal(t, tc.expectedError, capturedEvent.ErrorCode)
		})
	}
}

func TestPolicyMiddleware_DecisionCaching(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "cache-test-001",
		},
	}

	cache := pip.NewInMemoryCache()

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMDelegate,
		DecisionCache:   cache,
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	// First request: should hit PDP
	req1 := httptest.NewRequest("GET", "/v1/agents/abc", nil)
	req1.Header.Set("X-Capiscio-Badge", ts.token)
	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, req1)

	assert.Equal(t, http.StatusOK, rr1.Code)
	assert.Equal(t, 1, pdp.callCount())

	// Second request (same path): should hit cache, NOT PDP
	var secondEvent gateway.PolicyEvent
	callback := func(event gateway.PolicyEvent, req *pip.DecisionRequest) {
		secondEvent = event
	}
	mw2 := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

	req2 := httptest.NewRequest("GET", "/v1/agents/abc", nil)
	req2.Header.Set("X-Capiscio-Badge", ts.token)
	rr2 := httptest.NewRecorder()
	mw2.ServeHTTP(rr2, req2)

	assert.Equal(t, http.StatusOK, rr2.Code)
	assert.Equal(t, 1, pdp.callCount(), "PDP should not be called again when cache hit")
	assert.True(t, secondEvent.CacheHit)
}

func TestPolicyMiddleware_CachedDenyBlocks(t *testing.T) {
	ts := newTestSetup(t)

	// Setup a PDP that returns DENY, with DENY caching enabled
	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionDeny,
			DecisionID: "deny-cache-001",
		},
	}

	cache := pip.NewInMemoryCache(pip.WithCacheDeny(true))

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMDelegate,
		DecisionCache:   cache,
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	// First request — hits PDP, gets DENY, caches it
	req1 := httptest.NewRequest("GET", "/v1/deny-path", nil)
	req1.Header.Set("X-Capiscio-Badge", ts.token)
	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusForbidden, rr1.Code)
	assert.Equal(t, 1, pdp.callCount())

	// Second request — uses cache, PDP not called
	var event gateway.PolicyEvent
	callback := func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e }
	mw2 := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

	req2 := httptest.NewRequest("GET", "/v1/deny-path", nil)
	req2.Header.Set("X-Capiscio-Badge", ts.token)
	rr2 := httptest.NewRecorder()
	mw2.ServeHTTP(rr2, req2)

	assert.Equal(t, http.StatusForbidden, rr2.Code)
	assert.Equal(t, 1, pdp.callCount(), "PDP should not be called when cache has DENY")
	assert.True(t, event.CacheHit)
	assert.Equal(t, pip.DecisionDeny, event.Decision)
}

func TestPolicyMiddleware_Obligations(t *testing.T) {
	ts := newTestSetup(t)

	t.Run("known obligation succeeds", func(t *testing.T) {
		pdp := &mockPDP{
			resp: &pip.DecisionResponse{
				Decision:    pip.DecisionAllow,
				DecisionID:  "obl-001",
				Obligations: []pip.Obligation{{Type: "rate_limit", Params: json.RawMessage(`{}`)}},
			},
		}

		reg := pip.NewObligationRegistry(slog.Default())
		reg.Register(&mockObligationHandler{supported: "rate_limit"})

		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			ObligationReg:   reg,
		}

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("obligation failure in EM-STRICT blocks", func(t *testing.T) {
		pdp := &mockPDP{
			resp: &pip.DecisionResponse{
				Decision:    pip.DecisionAllow,
				DecisionID:  "obl-002",
				Obligations: []pip.Obligation{{Type: "rate_limit", Params: json.RawMessage(`{}`)}},
			},
		}

		reg := pip.NewObligationRegistry(slog.Default())
		reg.Register(&mockObligationHandler{supported: "rate_limit", err: fmt.Errorf("rate limit exceeded")})

		var event gateway.PolicyEvent
		callback := func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e }

		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			ObligationReg:   reg,
		}

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, pip.DecisionDeny, event.Decision)
	})

	t.Run("obligation failure in EM-OBSERVE allows through", func(t *testing.T) {
		pdp := &mockPDP{
			resp: &pip.DecisionResponse{
				Decision:    pip.DecisionAllow,
				DecisionID:  "obl-003",
				Obligations: []pip.Obligation{{Type: "rate_limit", Params: json.RawMessage(`{}`)}},
			},
		}

		reg := pip.NewObligationRegistry(slog.Default())
		reg.Register(&mockObligationHandler{supported: "rate_limit", err: fmt.Errorf("rate limit exceeded")})

		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMObserve,
			ObligationReg:   reg,
		}

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		// EM-OBSERVE: obligation failures are logged but not blocking
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("unknown obligation in EM-STRICT denies", func(t *testing.T) {
		pdp := &mockPDP{
			resp: &pip.DecisionResponse{
				Decision:    pip.DecisionAllow,
				DecisionID:  "obl-004",
				Obligations: []pip.Obligation{{Type: "unknown_obligation", Params: json.RawMessage(`{}`)}},
			},
		}

		reg := pip.NewObligationRegistry(slog.Default())
		// No handler registered for "unknown_obligation"

		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			ObligationReg:   reg,
		}

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestPolicyMiddleware_BreakGlass(t *testing.T) {
	ts := newTestSetup(t)

	// Generate a separate key pair for break-glass (NOT the badge key!)
	bgPub, bgPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionDeny,
			DecisionID: "would-deny-001",
		},
	}

	t.Run("valid break-glass bypasses PDP", func(t *testing.T) {
		var event gateway.PolicyEvent
		callback := func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e }

		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			BreakGlassKey:   bgPub,
		}

		bgToken := &pip.BreakGlassToken{
			JTI:    "bg-001",
			IAT:    time.Now().Unix(),
			EXP:    time.Now().Add(5 * time.Minute).Unix(),
			ISS:    "root-admin",
			SUB:    "operator-alice",
			Scope:  pip.BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
			Reason: "emergency: PDP outage investigation",
		}

		compact := signBreakGlassToken(t, bgPriv, bgToken)

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		req.Header.Set("X-Capiscio-Breakglass", compact)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, 0, pdp.callCount(), "PDP should NOT be called when break-glass active")
		assert.True(t, event.Override)
		assert.Equal(t, "bg-001", event.OverrideJTI)
		assert.Equal(t, pip.DecisionAllow, event.Decision)
	})

	t.Run("break-glass with wrong key is ignored", func(t *testing.T) {
		_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			BreakGlassKey:   bgPub,
		}

		bgToken := &pip.BreakGlassToken{
			JTI:    "bg-bad",
			IAT:    time.Now().Unix(),
			EXP:    time.Now().Add(5 * time.Minute).Unix(),
			ISS:    "root-admin",
			SUB:    "operator-evil",
			Scope:  pip.BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
			Reason: "trying to bypass",
		}

		compact := signBreakGlassToken(t, wrongPriv, bgToken)

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		req.Header.Set("X-Capiscio-Breakglass", compact)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		// Wrong key = token ignored = falls through to PDP which DENYs
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("expired break-glass is ignored", func(t *testing.T) {
		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			BreakGlassKey:   bgPub,
		}

		bgToken := &pip.BreakGlassToken{
			JTI:    "bg-expired",
			IAT:    time.Now().Add(-10 * time.Minute).Unix(),
			EXP:    time.Now().Add(-5 * time.Minute).Unix(), // expired
			ISS:    "root-admin",
			SUB:    "operator-alice",
			Scope:  pip.BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
			Reason: "expired token",
		}

		compact := signBreakGlassToken(t, bgPriv, bgToken)

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		req.Header.Set("X-Capiscio-Breakglass", compact)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusForbidden, rr.Code)
	})

	t.Run("break-glass scope mismatch is ignored", func(t *testing.T) {
		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMStrict,
			BreakGlassKey:   bgPub,
		}

		bgToken := &pip.BreakGlassToken{
			JTI:    "bg-scoped",
			IAT:    time.Now().Unix(),
			EXP:    time.Now().Add(5 * time.Minute).Unix(),
			ISS:    "root-admin",
			SUB:    "operator-alice",
			Scope:  pip.BreakGlassScope{Methods: []string{"POST"}, Routes: []string{"/v1/different"}},
			Reason: "scoped override",
		}

		compact := signBreakGlassToken(t, bgPriv, bgToken)

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		req.Header.Set("X-Capiscio-Breakglass", compact)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		// Scope doesn't match (GET != POST, /v1/agents != /v1/different)
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestPolicyMiddleware_TxnIDPropagation(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "txn-test-001",
		},
	}

	t.Run("generates txn_id when absent", func(t *testing.T) {
		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMObserve,
		}

		var capturedTxnID string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedTxnID = r.Header.Get(pip.TxnIDHeader)
			w.WriteHeader(http.StatusOK)
		})

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, next)

		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.NotEmpty(t, capturedTxnID, "txn_id should be generated and forwarded")
		assert.Equal(t, capturedTxnID, pdp.lastRequest().Context.TxnID)
	})

	t.Run("reuses existing txn_id from header", func(t *testing.T) {
		config := gateway.PEPConfig{
			PDPClient:       pdp,
			EnforcementMode: pip.EMObserve,
		}

		mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

		existingTxnID := "019471a2-1234-7abc-9def-abcdef123456"
		req := httptest.NewRequest("GET", "/v1/agents", nil)
		req.Header.Set("X-Capiscio-Badge", ts.token)
		req.Header.Set(pip.TxnIDHeader, existingTxnID)
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, req)

		assert.Equal(t, existingTxnID, pdp.lastRequest().Context.TxnID)
	})
}

func TestPolicyMiddleware_EnvironmentAttrs(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "env-001",
		},
	}

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMObserve,
		PEPID:           "pep-gateway-01",
		Workspace:       "acme-corp",
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	req := httptest.NewRequest("POST", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	pipReq := pdp.lastRequest()
	require.NotNil(t, pipReq.Environment.PEPID)
	assert.Equal(t, "pep-gateway-01", *pipReq.Environment.PEPID)
	require.NotNil(t, pipReq.Environment.Workspace)
	assert.Equal(t, "acme-corp", *pipReq.Environment.Workspace)
	require.NotNil(t, pipReq.Environment.Time)
	// Time should be parseable RFC3339
	_, err := time.Parse(time.RFC3339, *pipReq.Environment.Time)
	assert.NoError(t, err)
}

func TestPolicyMiddleware_NullEnvelopeFields(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "null-env-001",
		},
	}

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMObserve,
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	pipReq := pdp.lastRequest()
	// Badge-only mode: envelope fields MUST be null
	assert.Nil(t, pipReq.Action.CapabilityClass)
	assert.Nil(t, pipReq.Context.EnvelopeID)
	assert.Nil(t, pipReq.Context.DelegationDepth)
	assert.Nil(t, pipReq.Context.Constraints)
	assert.Nil(t, pipReq.Context.ParentConstraints)
	assert.Nil(t, pipReq.Context.HopID)
}

func TestPolicyMiddleware_EventCallbackReceivesObligationTypes(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "obl-event-001",
			Obligations: []pip.Obligation{
				{Type: "rate_limit", Params: json.RawMessage(`{"rps": 100}`)},
				{Type: "enhanced_logging", Params: json.RawMessage(`{}`)},
			},
		},
	}

	var event gateway.PolicyEvent
	callback := func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e }

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMObserve,
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"rate_limit", "enhanced_logging"}, event.Obligations)
}

func TestPolicyMiddleware_PDPLatencyTracked(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "latency-001",
		},
	}

	var event gateway.PolicyEvent
	callback := func(e gateway.PolicyEvent, _ *pip.DecisionRequest) { event = e }

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMObserve,
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler(), callback)

	req := httptest.NewRequest("GET", "/v1/agents", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.GreaterOrEqual(t, event.PDPLatencyMs, int64(0))
}

func TestPolicyMiddleware_HeaderForwarding(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:   pip.DecisionAllow,
			DecisionID: "header-001",
		},
	}

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMObserve,
	}

	var capturedSubject, capturedIssuer string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSubject = r.Header.Get("X-Capiscio-Subject")
		capturedIssuer = r.Header.Get("X-Capiscio-Issuer")
		w.WriteHeader(http.StatusOK)
	})

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, next)

	req := httptest.NewRequest("GET", "/v1/test", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, ts.claims.Subject, capturedSubject)
	assert.Equal(t, ts.claims.Issuer, capturedIssuer)
}

func TestParseBreakGlassJWS(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("valid token", func(t *testing.T) {
		bgToken := &pip.BreakGlassToken{
			JTI:    "bg-parse-001",
			IAT:    time.Now().Unix(),
			EXP:    time.Now().Add(5 * time.Minute).Unix(),
			ISS:    "root-admin",
			SUB:    "operator-bob",
			Scope:  pip.BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
			Reason: "testing parse",
		}

		compact := signBreakGlassToken(t, priv, bgToken)

		parsed, err := pip.ParseBreakGlassJWS(compact, pub)
		require.NoError(t, err)
		assert.Equal(t, bgToken.JTI, parsed.JTI)
		assert.Equal(t, bgToken.ISS, parsed.ISS)
		assert.Equal(t, bgToken.SUB, parsed.SUB)
		assert.Equal(t, bgToken.Reason, parsed.Reason)
	})

	t.Run("wrong key fails", func(t *testing.T) {
		bgToken := &pip.BreakGlassToken{
			JTI:    "bg-parse-002",
			IAT:    time.Now().Unix(),
			EXP:    time.Now().Add(5 * time.Minute).Unix(),
			ISS:    "root-admin",
			SUB:    "operator-bob",
			Scope:  pip.BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
			Reason: "testing wrong key",
		}

		compact := signBreakGlassToken(t, priv, bgToken)

		wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		_, err = pip.ParseBreakGlassJWS(compact, wrongPub)
		assert.Error(t, err)
	})

	t.Run("invalid compact JWS fails", func(t *testing.T) {
		_, err := pip.ParseBreakGlassJWS("not-a-jws", pub)
		assert.Error(t, err)
	})
}

func TestPolicyMiddleware_ScopeInsufficientJSON(t *testing.T) {
	ts := newTestSetup(t)

	pdp := &mockPDP{
		resp: &pip.DecisionResponse{
			Decision:            pip.DecisionDeny,
			DecisionID:          "deny-scope-1",
			Reason:              "capability class mismatch",
			ErrorCode:           "SCOPE_INSUFFICIENT",
			RequestedCapability: "storage",
		},
	}

	config := gateway.PEPConfig{
		PDPClient:       pdp,
		EnforcementMode: pip.EMStrict,
	}
	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	req := httptest.NewRequest("GET", "/v1/data", nil)
	req.Header.Set("X-Capiscio-Badge", ts.token)
	rr := httptest.NewRecorder()

	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var body envelope.ScopeInsufficientRejection
	err := json.NewDecoder(rr.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, envelope.ErrCodeScopeInsufficient, body.Error)
	assert.Equal(t, "storage", body.RequestedCapability)
}

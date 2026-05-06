package gateway_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/capiscio/capiscio-core/v2/pkg/gateway"
	"github.com/capiscio/capiscio-core/v2/pkg/pip"
)

// chainTestSetup extends testSetup with envelope/chain infrastructure.
type chainTestSetup struct {
	*testSetup

	// Envelope key pairs (distinct from badge keys).
	issuerPub  ed25519.PublicKey
	issuerPriv ed25519.PrivateKey
	issuerDID  string

	delegatePub  ed25519.PublicKey
	delegatePriv ed25519.PrivateKey
	delegateDID  string

	leafPub ed25519.PublicKey
	leafDID string

	envelopeVerifier *envelope.Verifier
}

func newChainTestSetup(t *testing.T) *chainTestSetup {
	t.Helper()
	ts := newTestSetup(t)

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	delegatePub, delegatePriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	leafPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return &chainTestSetup{
		testSetup:    ts,
		issuerPub:    issuerPub,
		issuerPriv:   issuerPriv,
		issuerDID:    did.NewKeyDID(issuerPub),
		delegatePub:  delegatePub,
		delegatePriv: delegatePriv,
		delegateDID:  did.NewKeyDID(delegatePub),
		leafPub:      leafPub,
		leafDID:      did.NewKeyDID(leafPub),
		envelopeVerifier: &envelope.Verifier{
			KeyResolver: envelope.DefaultKeyResolver,
		},
	}
}

// issueRootEnvelope creates a root envelope signed by the issuer.
func (s *chainTestSetup) issueRootEnvelope(t *testing.T, capability string, depth int) string {
	t.Helper()
	now := time.Now()
	payload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                s.issuerDID,
		SubjectDID:               s.delegateDID,
		TxnID:                    uuid.New().String(),
		CapabilityClass:          capability,
		Constraints:              map[string]any{},
		DelegationDepthRemaining: depth,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}
	token, err := envelope.SignEnvelope(payload, s.issuerPriv, s.issuerDID+"#key-1")
	require.NoError(t, err)
	return token
}

// deriveChildEnvelope creates a child envelope from a parent.
func (s *chainTestSetup) deriveChildEnvelope(
	t *testing.T,
	parentJWS string,
	capability string,
	depth int,
	signerPriv ed25519.PrivateKey,
	signerDID string,
	subjectDID string,
) string {
	t.Helper()
	parent, err := envelope.ParseToken(parentJWS)
	require.NoError(t, err)

	now := time.Now()
	child := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                signerDID,
		SubjectDID:               subjectDID,
		TxnID:                    parent.Payload.TxnID,
		CapabilityClass:          capability,
		Constraints:              map[string]any{},
		DelegationDepthRemaining: depth,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(30 * time.Minute).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}
	childJWS, err := envelope.DeriveEnvelope(parent, child, signerPriv, signerDID+"#key-1")
	require.NoError(t, err)
	return childJWS
}

// encodeChainHeader base64url-encodes a chain (JSON array of JWS strings).
func encodeChainHeader(t *testing.T, chain []string) string {
	t.Helper()
	b, err := json.Marshal(chain)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

// sendChainRequest creates a request with badge + chain headers and serves it through the middleware.
func (s *chainTestSetup) sendChainRequest(
	t *testing.T,
	config gateway.PEPConfig,
	leafJWS string,
	chain []string,
) *httptest.ResponseRecorder {
	t.Helper()
	mw := gateway.NewPolicyMiddleware(s.verifier, config, okHandler())
	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	r.Header.Set("X-Capiscio-Badge", s.token)
	r.Header.Set(gateway.HeaderAuthority, leafJWS)
	if chain != nil {
		r.Header.Set(gateway.HeaderAuthorityChain, encodeChainHeader(t, chain))
	}
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	return w
}

// --- Integration Tests ---

func TestChainVerification_BadgeOnlyBackwardCompat(t *testing.T) {
	ts := newChainTestSetup(t)

	// EnvelopeVerifier is set, but no chain headers → should proceed as badge-only.
	pdp := &mockPDP{resp: &pip.DecisionResponse{
		Decision:   pip.DecisionAllow,
		DecisionID: "d-1",
	}}
	config := gateway.PEPConfig{
		PDPClient:        pdp,
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
	}
	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())

	// No envelope headers at all.
	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	r.Header.Set("X-Capiscio-Badge", ts.token)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	// PDP should have been called with nil envelope fields.
	req := pdp.lastRequest()
	require.NotNil(t, req)
	assert.Nil(t, req.Context.DelegationDepth)
}

func TestChainVerification_SingleEnvelope(t *testing.T) {
	ts := newChainTestSetup(t)

	rootJWS := ts.issueRootEnvelope(t, "tools.database.read", 3)

	pdp := &mockPDP{resp: &pip.DecisionResponse{
		Decision:   pip.DecisionAllow,
		DecisionID: "d-2",
	}}
	config := gateway.PEPConfig{
		PDPClient:        pdp,
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
	}

	// Send with X-Capiscio-Authority but no chain → treated as single-element chain.
	w := ts.sendChainRequest(t, config, rootJWS, nil)

	assert.Equal(t, http.StatusOK, w.Code)
	req := pdp.lastRequest()
	require.NotNil(t, req)
	// Verified capability class should override any raw header.
	require.NotNil(t, req.Action.CapabilityClass)
	assert.Equal(t, "tools.database.read", *req.Action.CapabilityClass)
}

func TestChainVerification_TwoHopChain(t *testing.T) {
	ts := newChainTestSetup(t)

	rootJWS := ts.issueRootEnvelope(t, "tools.database", 3)
	childJWS := ts.deriveChildEnvelope(t, rootJWS, "tools.database.read", 2,
		ts.delegatePriv, ts.delegateDID, ts.leafDID)

	pdp := &mockPDP{resp: &pip.DecisionResponse{
		Decision:   pip.DecisionAllow,
		DecisionID: "d-3",
	}}
	config := gateway.PEPConfig{
		PDPClient:        pdp,
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
	}

	chain := []string{rootJWS, childJWS}
	w := ts.sendChainRequest(t, config, childJWS, chain)

	assert.Equal(t, http.StatusOK, w.Code)
	req := pdp.lastRequest()
	require.NotNil(t, req)

	// Leaf capability should be the narrowed one.
	require.NotNil(t, req.Action.CapabilityClass)
	assert.Equal(t, "tools.database.read", *req.Action.CapabilityClass)

	// Delegation depth should be populated.
	require.NotNil(t, req.Context.DelegationDepth)
	assert.Equal(t, 1, *req.Context.DelegationDepth) // 1 hop

	// EnvelopeID should be from the leaf envelope.
	require.NotNil(t, req.Context.EnvelopeID)
	assert.NotEmpty(t, *req.Context.EnvelopeID)
}

func TestChainVerification_VerifiedCapabilityOverridesRawHeader(t *testing.T) {
	ts := newChainTestSetup(t)

	rootJWS := ts.issueRootEnvelope(t, "tools.database.read", 3)

	pdp := &mockPDP{resp: &pip.DecisionResponse{
		Decision:   pip.DecisionAllow,
		DecisionID: "d-4",
	}}
	config := gateway.PEPConfig{
		PDPClient:        pdp,
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
	}

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())
	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	r.Header.Set("X-Capiscio-Badge", ts.token)
	r.Header.Set(gateway.HeaderAuthority, rootJWS)
	// Attacker tries to inject a broader capability via raw header.
	r.Header.Set("X-Capiscio-Capability-Class", "tools.*")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	req := pdp.lastRequest()
	require.NotNil(t, req)
	// The verified LeafCapability should win, not the injected header.
	require.NotNil(t, req.Action.CapabilityClass)
	assert.Equal(t, "tools.database.read", *req.Action.CapabilityClass)
}

func TestChainVerification_ChainTooDeep(t *testing.T) {
	ts := newChainTestSetup(t)

	config := gateway.PEPConfig{
		PDPClient:        &mockPDP{},
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
		MaxChainDepth:    1, // Only allow single envelope.
	}

	rootJWS := ts.issueRootEnvelope(t, "tools.database", 3)
	childJWS := ts.deriveChildEnvelope(t, rootJWS, "tools.database.read", 2,
		ts.delegatePriv, ts.delegateDID, ts.leafDID)

	chain := []string{rootJWS, childJWS}
	w := ts.sendChainRequest(t, config, childJWS, chain)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "ENVELOPE_CHAIN_TOO_DEEP", body["error"])
}

func TestChainVerification_MalformedChainHeader(t *testing.T) {
	ts := newChainTestSetup(t)

	config := gateway.PEPConfig{
		PDPClient:        &mockPDP{},
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
	}

	rootJWS := ts.issueRootEnvelope(t, "tools.database.read", 3)

	mw := gateway.NewPolicyMiddleware(ts.verifier, config, okHandler())
	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	r.Header.Set("X-Capiscio-Badge", ts.token)
	r.Header.Set(gateway.HeaderAuthority, rootJWS)
	r.Header.Set(gateway.HeaderAuthorityChain, "!!!not-base64!!!")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "ENVELOPE_MALFORMED", body["error"])
}

func TestChainVerification_LeafInconsistency(t *testing.T) {
	ts := newChainTestSetup(t)

	config := gateway.PEPConfig{
		PDPClient:        &mockPDP{},
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: ts.envelopeVerifier,
	}

	rootJWS := ts.issueRootEnvelope(t, "tools.database", 3)
	childJWS := ts.deriveChildEnvelope(t, rootJWS, "tools.database.read", 2,
		ts.delegatePriv, ts.delegateDID, ts.leafDID)

	// Chain says [root, child] but leaf header is root (inconsistent).
	chain := []string{rootJWS, childJWS}
	w := ts.sendChainRequest(t, config, rootJWS, chain) // leaf != chain[-1]

	assert.Equal(t, http.StatusForbidden, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "ENVELOPE_CHAIN_BROKEN", body["error"])
}

func TestChainVerification_NilVerifierSkipsChain(t *testing.T) {
	ts := newChainTestSetup(t)

	pdp := &mockPDP{resp: &pip.DecisionResponse{
		Decision:   pip.DecisionAllow,
		DecisionID: "d-5",
	}}
	config := gateway.PEPConfig{
		PDPClient:        pdp,
		EnforcementMode:  pip.EMDelegate,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
		EnvelopeVerifier: nil, // Explicitly nil — chain verification disabled.
	}

	rootJWS := ts.issueRootEnvelope(t, "tools.database.read", 3)

	// Even with authority headers present, they should be ignored.
	w := ts.sendChainRequest(t, config, rootJWS, []string{rootJWS})

	assert.Equal(t, http.StatusOK, w.Code)
	req := pdp.lastRequest()
	require.NotNil(t, req)
	// Without EnvelopeVerifier, raw header should be used (or nil).
	assert.Nil(t, req.Context.DelegationDepth)
}

func TestChainVerification_ErrorCodesHTTPMapping(t *testing.T) {
	tests := []struct {
		code       string
		wantStatus int
	}{
		{envelope.ErrCodeMalformed, http.StatusBadRequest},
		{envelope.ErrCodeCapabilityInvalid, http.StatusBadRequest},
		{envelope.ErrCodePayloadTooLarge, http.StatusBadRequest},
		{envelope.ErrCodeExpired, http.StatusUnauthorized},
		{envelope.ErrCodeNotYetValid, http.StatusUnauthorized},
		{envelope.ErrCodeSignatureInvalid, http.StatusForbidden},
		{envelope.ErrCodeChainBroken, http.StatusForbidden},
		{envelope.ErrCodeNarrowingViolation, http.StatusForbidden},
		{envelope.ErrCodeDepthExceeded, http.StatusForbidden},
		{envelope.ErrCodeChainTooDeep, http.StatusForbidden},
		{envelope.ErrCodeKeyNotBound, http.StatusForbidden},
		{envelope.ErrCodeScopeInsufficient, http.StatusForbidden},
		{envelope.ErrCodeAlgorithmForbidden, http.StatusForbidden},
		{envelope.ErrCodeBadgeBindingFailed, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			status := gateway.ChainErrorHTTPStatus(tt.code)
			assert.Equal(t, tt.wantStatus, status, "wrong HTTP status for %s", tt.code)
		})
	}
}

func TestChainVerification_EMObservePassesThrough(t *testing.T) {
	ts := newChainTestSetup(t)

	// Create a chain with a tampered envelope (will fail verification)
	rootJWS := ts.issueRootEnvelope(t, "tools.database.read", 2)
	tamperedJWS := rootJWS + "tampered" // corrupt the signature

	config := gateway.PEPConfig{
		EnvelopeVerifier: ts.envelopeVerifier,
		MaxChainDepth:    10,
		EnforcementMode:  pip.EMObserve, // observe mode — should pass through
		PDPClient:        &mockPDP{resp: &pip.DecisionResponse{Decision: pip.DecisionAllow, DecisionID: "d-obs"}},
		PEPID:            "test-pep",
		Workspace:        "test-ws",
	}

	w := ts.sendChainRequest(t, config, tamperedJWS, nil)

	// In EM-OBSERVE, chain errors are logged but request proceeds
	assert.Equal(t, http.StatusOK, w.Code, "EM-OBSERVE should allow request despite chain error")
}

func TestChainVerification_EnforcementModeEscalation(t *testing.T) {
	ptrStr := func(s string) *string { return &s }

	ts := newChainTestSetup(t)

	// Create a root envelope with enforcement_mode_min = EM-STRICT
	now := time.Now()
	rootPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                ts.issuerDID,
		SubjectDID:               ts.delegateDID,
		TxnID:                    uuid.New().String(),
		CapabilityClass:          "tools.database.read",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 2,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
		EnforcementModeMin:       ptrStr("EM-STRICT"), // escalate to strict
	}
	rootJWS, err := envelope.SignEnvelope(rootPayload, ts.issuerPriv, ts.issuerDID+"#key-1")
	require.NoError(t, err)

	// PEP is configured as EM-OBSERVE, but envelope mandates EM-STRICT
	pdp := &mockPDP{resp: &pip.DecisionResponse{
		Decision:   pip.DecisionAllow,
		DecisionID: "d-esc",
	}}
	config := gateway.PEPConfig{
		EnvelopeVerifier: ts.envelopeVerifier,
		MaxChainDepth:    10,
		EnforcementMode:  pip.EMObserve,
		PDPClient:        pdp,
		PEPID:            "test-pep",
		Workspace:        "test-ws",
	}

	w := ts.sendChainRequest(t, config, rootJWS, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the PDP received the escalated enforcement mode
	lastReq := pdp.lastRequest()
	require.NotNil(t, lastReq)
	assert.Equal(t, "EM-STRICT", lastReq.Context.EnforcementMode,
		"PDP should receive escalated enforcement mode from envelope")
}

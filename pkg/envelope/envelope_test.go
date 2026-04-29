package envelope_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func testDID(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	return did.NewKeyDID(pub)
}

func testPayload(t *testing.T, issuerDID, subjectDID string) *envelope.Payload {
	t.Helper()
	now := time.Now()
	return &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               subjectDID,
		TxnID:                    uuid.New().String(),
		ParentAuthorityHash:      nil,
		CapabilityClass:          "tools.database.read",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 5,
		EnforcementModeMin:       nil,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(1 * time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
		SubjectBadgeJTI:          nil,
	}
}

func TestSignEnvelope_RoundTrip(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)

	// Sign
	token, err := envelope.SignEnvelope(payload, priv, issuerDID+"#key-1")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Parse back
	parsed, err := envelope.ParseToken(token)
	require.NoError(t, err)
	assert.Equal(t, payload.EnvelopeID, parsed.Payload.EnvelopeID)
	assert.Equal(t, payload.IssuerDID, parsed.Payload.IssuerDID)
	assert.Equal(t, payload.SubjectDID, parsed.Payload.SubjectDID)
	assert.Equal(t, payload.TxnID, parsed.Payload.TxnID)
	assert.Equal(t, payload.CapabilityClass, parsed.Payload.CapabilityClass)
	assert.Equal(t, payload.DelegationDepthRemaining, parsed.Payload.DelegationDepthRemaining)
	assert.Equal(t, payload.IssuedAt, parsed.Payload.IssuedAt)
	assert.Equal(t, payload.ExpiresAt, parsed.Payload.ExpiresAt)
	assert.Equal(t, payload.IssuerBadgeJTI, parsed.Payload.IssuerBadgeJTI)
	assert.Nil(t, parsed.Payload.ParentAuthorityHash)
	assert.Nil(t, parsed.Payload.SubjectBadgeJTI)
	assert.True(t, parsed.Payload.IsRoot())
}

func TestSignEnvelope_WithOptionalFields(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	now := time.Now()
	emStr := "EM-STRICT"
	subBadgeJTI := uuid.New().String()
	parentHash := "abc123def456"

	payload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               subjectDID,
		TxnID:                    uuid.New().String(),
		ParentAuthorityHash:      &parentHash,
		CapabilityClass:          "tools.database",
		Constraints:              map[string]any{"max_rows": float64(100)},
		DelegationDepthRemaining: 3,
		EnforcementModeMin:       &emStr,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(30 * time.Minute).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
		SubjectBadgeJTI:          &subBadgeJTI,
	}

	token, err := envelope.SignEnvelope(payload, priv, issuerDID+"#key-1")
	require.NoError(t, err)

	parsed, err := envelope.ParseToken(token)
	require.NoError(t, err)
	assert.Equal(t, &parentHash, parsed.Payload.ParentAuthorityHash)
	assert.Equal(t, &emStr, parsed.Payload.EnforcementModeMin)
	assert.Equal(t, &subBadgeJTI, parsed.Payload.SubjectBadgeJTI)
	assert.False(t, parsed.Payload.IsRoot())
	assert.Equal(t, float64(100), parsed.Payload.Constraints["max_rows"])
}

func TestSignEnvelope_InvalidPayload(t *testing.T) {
	_, priv := generateTestKey(t)

	tests := []struct {
		name    string
		modify  func(*envelope.Payload)
		wantErr string
	}{
		{
			name:    "missing envelope_id",
			modify:  func(p *envelope.Payload) { p.EnvelopeID = "" },
			wantErr: "envelope_id",
		},
		{
			name:    "missing issuer_did",
			modify:  func(p *envelope.Payload) { p.IssuerDID = "" },
			wantErr: "issuer_did",
		},
		{
			name:    "missing subject_did",
			modify:  func(p *envelope.Payload) { p.SubjectDID = "" },
			wantErr: "subject_did",
		},
		{
			name:    "missing txn_id",
			modify:  func(p *envelope.Payload) { p.TxnID = "" },
			wantErr: "txn_id",
		},
		{
			name:    "invalid capability class",
			modify:  func(p *envelope.Payload) { p.CapabilityClass = "Invalid.Class" },
			wantErr: "CAPABILITY",
		},
		{
			name:    "nil constraints",
			modify:  func(p *envelope.Payload) { p.Constraints = nil },
			wantErr: "constraints",
		},
		{
			name:    "negative depth",
			modify:  func(p *envelope.Payload) { p.DelegationDepthRemaining = -1 },
			wantErr: "delegation_depth_remaining",
		},
		{
			name:    "invalid enforcement mode",
			modify:  func(p *envelope.Payload) { s := "INVALID"; p.EnforcementModeMin = &s },
			wantErr: "enforcement mode",
		},
		{
			name:    "expires_at before issued_at",
			modify:  func(p *envelope.Payload) { p.ExpiresAt = p.IssuedAt - 1 },
			wantErr: "expires_at",
		},
		{
			name:    "missing issuer_badge_jti",
			modify:  func(p *envelope.Payload) { p.IssuerBadgeJTI = "" },
			wantErr: "issuer_badge_jti",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, _ := generateTestKey(t)
			payload := testPayload(t, testDID(t, pub), "did:key:z6MkSubject")
			tt.modify(payload)
			_, err := envelope.SignEnvelope(payload, priv, "did:key:test#key-1")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestComputeHash(t *testing.T) {
	hash := envelope.ComputeHash("test-jws-string")
	assert.Len(t, hash, 64) // SHA-256 hex is 64 chars
	assert.Equal(t, strings.ToLower(hash), hash) // lowercase

	// Same input = same output
	hash2 := envelope.ComputeHash("test-jws-string")
	assert.Equal(t, hash, hash2)

	// Different input = different output
	hash3 := envelope.ComputeHash("different-jws-string")
	assert.NotEqual(t, hash, hash3)
}

func TestParseToken_InvalidJWS(t *testing.T) {
	_, err := envelope.ParseToken("not-a-valid-jws")
	require.Error(t, err)

	var envErr *envelope.Error
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "ENVELOPE_MALFORMED", envErr.Code)
}

func TestPayload_JSONMarshal(t *testing.T) {
	now := time.Now()
	p := &envelope.Payload{
		EnvelopeID:               "test-id",
		IssuerDID:                "did:key:issuer",
		SubjectDID:               "did:key:subject",
		TxnID:                    "txn-1",
		CapabilityClass:          "tools",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 3,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		IssuerBadgeJTI:           "badge-1",
	}

	data, err := json.Marshal(p)
	require.NoError(t, err)

	var decoded envelope.Payload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, p.EnvelopeID, decoded.EnvelopeID)
	assert.Nil(t, decoded.ParentAuthorityHash)
	assert.Nil(t, decoded.SubjectBadgeJTI)
	assert.Nil(t, decoded.EnforcementModeMin)
}

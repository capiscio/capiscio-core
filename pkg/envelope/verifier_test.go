package envelope_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeyResolver maps DIDs to public keys for testing.
type testKeyResolver struct {
	keys map[string]crypto.PublicKey
}

func (r *testKeyResolver) resolve(_ context.Context, didStr string, _ string) (crypto.PublicKey, error) {
	if key, ok := r.keys[didStr]; ok {
		return key, nil
	}
	return envelope.DefaultKeyResolver(context.Background(), didStr, "")
}

func newResolver(pairs ...interface{}) *testKeyResolver {
	r := &testKeyResolver{keys: make(map[string]crypto.PublicKey)}
	for i := 0; i < len(pairs); i += 2 {
		r.keys[pairs[i].(string)] = pairs[i+1].(crypto.PublicKey)
	}
	return r
}

func signTestEnvelope(t *testing.T, payload *envelope.Payload, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	token, err := envelope.SignEnvelope(payload, priv, kid)
	require.NoError(t, err)
	return token
}

func TestVerifyEnvelope_ValidRootEnvelope(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)

	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	v := &envelope.Verifier{
		KeyResolver: envelope.DefaultKeyResolver,
	}

	result, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.NoError(t, err)
	assert.Equal(t, payload.EnvelopeID, result.Payload.EnvelopeID)
	assert.Equal(t, payload.IssuerDID, result.Payload.IssuerDID)
	assert.Equal(t, payload.SubjectDID, result.Payload.SubjectDID)
}

func TestVerifyEnvelope_ExpiredEnvelope(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)
	payload.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix() // expired
	payload.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()

	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	_, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.Error(t, err)

	var envErr *envelope.Error
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "ENVELOPE_EXPIRED", envErr.Code)
}

func TestVerifyEnvelope_FutureIssuedAt(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)
	payload.IssuedAt = time.Now().Add(2 * time.Hour).Unix()    // future
	payload.ExpiresAt = time.Now().Add(3 * time.Hour).Unix()

	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	_, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.Error(t, err)

	var envErr *envelope.Error
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "ENVELOPE_NOT_YET_VALID", envErr.Code)
}

func TestVerifyEnvelope_WrongSigningKey(t *testing.T) {
	pub, _ := generateTestKey(t)
	issuerDID := testDID(t, pub)
	_, wrongPriv := generateTestKey(t) // different key
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)
	token := signTestEnvelope(t, payload, wrongPriv, issuerDID+"#key-1")

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	_, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.Error(t, err)

	var envErr *envelope.Error
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "ENVELOPE_SIGNATURE_INVALID", envErr.Code)
}

func TestVerifyEnvelope_EnforcementModeEscalation(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	emStr := "EM-STRICT"
	payload := testPayload(t, issuerDID, subjectDID)
	payload.EnforcementModeMin = &emStr

	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	result, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
		EnforcementMode:       envelope.EMObserve,
	})
	require.NoError(t, err)
	assert.Equal(t, envelope.EMStrict, result.EffectiveMode)
}

func TestVerifyEnvelope_MalformedJWS(t *testing.T) {
	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	_, err := v.VerifyEnvelope(context.Background(), "not.a.jws", "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.Error(t, err)

	var envErr *envelope.Error
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "ENVELOPE_MALFORMED", envErr.Code)
}

func TestVerifyEnvelope_TimeOverride(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := testPayload(t, issuerDID, subjectDID)
	payload.IssuedAt = now.Unix()
	payload.ExpiresAt = now.Add(time.Hour).Unix()

	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}

	// Without time override — current time is before issued_at
	_, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.Error(t, err)

	// With time override — should pass
	result, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
		Now:                   func() time.Time { return now.Add(30 * time.Minute) },
	})
	require.NoError(t, err)
	assert.Equal(t, payload.EnvelopeID, result.Payload.EnvelopeID)
}

func TestVerifyChain_ValidTwoHop(t *testing.T) {
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	pubC, _ := generateTestKey(t)

	didA := testDID(t, pubA)
	didB := testDID(t, pubB)
	didC := testDID(t, pubC)

	now := time.Now()
	txnID := uuid.New().String()

	// Root
	root := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                didA,
		SubjectDID:               didB,
		TxnID:                    txnID,
		CapabilityClass:          "tools.database",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 3,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}
	rootJWS := signTestEnvelope(t, root, privA, didA+"#key-1")
	rootToken, err := envelope.ParseToken(rootJWS)
	require.NoError(t, err)

	// Child
	child := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                didB,
		SubjectDID:               didC,
		TxnID:                    txnID,
		CapabilityClass:          "tools.database.read",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 2,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(30 * time.Minute).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}
	childJWS, err := envelope.DeriveEnvelope(rootToken, child, privB, didB+"#key-1")
	require.NoError(t, err)

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	result, err := v.VerifyChain(
		context.Background(),
		[]string{rootJWS, childJWS},
		map[string]string{},
		envelope.VerifyOptions{SkipBadgeVerification: true},
	)
	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Links))
	assert.Equal(t, "tools.database", result.RootCapability)
	assert.Equal(t, "tools.database.read", result.LeafCapability)
	assert.Equal(t, 1, result.TotalDepth)
}

func TestVerifyChain_Empty(t *testing.T) {
	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	_, err := v.VerifyChain(context.Background(), []string{}, map[string]string{}, envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.Error(t, err)
}

func TestVerifyEnvelope_PayloadTooLarge(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)
	// Add a large constraints field
	bigData := make(map[string]any)
	for i := 0; i < 500; i++ {
		bigData[uuid.New().String()] = uuid.New().String()
	}
	payload.Constraints = bigData

	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	v := &envelope.Verifier{KeyResolver: envelope.DefaultKeyResolver}
	_, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
		MaxPayloadSize:        100, // very small limit
	})
	require.Error(t, err)

	var envErr *envelope.Error
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "ENVELOPE_PAYLOAD_TOO_LARGE", envErr.Code)
}

func TestVerifyEnvelope_DefaultKeyResolver_DidKey(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	payload := testPayload(t, issuerDID, subjectDID)
	token := signTestEnvelope(t, payload, priv, issuerDID+"#key-1")

	// Verify using DefaultKeyResolver (did:key)
	v := &envelope.Verifier{} // nil KeyResolver → uses DefaultKeyResolver
	result, err := v.VerifyEnvelope(context.Background(), token, "", "", envelope.VerifyOptions{
		SkipBadgeVerification: true,
	})
	require.NoError(t, err)
	assert.Equal(t, payload.EnvelopeID, result.Payload.EnvelopeID)
}

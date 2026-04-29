package envelope_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildChain(t *testing.T, depth int) (envelope.Chain, []ed25519.PrivateKey, []ed25519.PublicKey) {
	t.Helper()

	// Generate keys for depth+1 participants (root issuer + depth subjects)
	keys := make([]ed25519.PrivateKey, depth+1)
	pubs := make([]ed25519.PublicKey, depth+1)
	for i := range keys {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keys[i] = priv
		pubs[i] = pub
	}

	dids := make([]string, len(pubs))
	for i, pub := range pubs {
		dids[i] = did.NewKeyDID(pub)
	}

	now := time.Now()
	txnID := uuid.New().String()

	// Root envelope
	rootPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                dids[0],
		SubjectDID:               dids[1],
		TxnID:                    txnID,
		CapabilityClass:          "tools.database",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: depth,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(1 * time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}

	rootJWS, err := envelope.SignEnvelope(rootPayload, keys[0], dids[0]+"#key-1")
	require.NoError(t, err)

	rootToken, err := envelope.ParseToken(rootJWS)
	require.NoError(t, err)

	chain := envelope.Chain{rootToken}

	// Derived envelopes
	for i := 1; i < depth; i++ {
		parent := chain[i-1]
		childPayload := &envelope.Payload{
			EnvelopeID:               uuid.New().String(),
			IssuerDID:                dids[i],
			SubjectDID:               dids[i+1],
			TxnID:                    txnID,
			CapabilityClass:          "tools.database.read",
			Constraints:              map[string]any{},
			DelegationDepthRemaining: depth - i,
			IssuedAt:                 now.Unix(),
			ExpiresAt:                now.Add(30 * time.Minute).Unix(),
			IssuerBadgeJTI:           uuid.New().String(),
			SubjectBadgeJTI:          ptrStr(uuid.New().String()),
		}

		childJWS, err := envelope.DeriveEnvelope(parent, childPayload, keys[i], dids[i]+"#key-1")
		require.NoError(t, err)

		childToken, err := envelope.ParseToken(childJWS)
		require.NoError(t, err)

		chain = append(chain, childToken)
	}

	return chain, keys, pubs
}

func ptrStr(s string) *string { return &s }

func TestChain_ValidThreeHop(t *testing.T) {
	chain, _, _ := buildChain(t, 3)
	require.Len(t, chain, 3)

	err := envelope.ValidateChainIntegrity(chain)
	require.NoError(t, err)
}

func TestChain_SingleRoot(t *testing.T) {
	chain, _, _ := buildChain(t, 1)
	require.Len(t, chain, 1)

	err := envelope.ValidateChainIntegrity(chain)
	require.NoError(t, err)
}

func TestChain_EmptyChainRejected(t *testing.T) {
	err := envelope.ValidateChainIntegrity(envelope.Chain{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestChain_TamperedHashLink(t *testing.T) {
	chain, _, _ := buildChain(t, 3)

	// Tamper with the hash link in the second envelope
	chain[1].Payload.ParentAuthorityHash = ptrStr("0000000000000000000000000000000000000000000000000000000000000000")

	err := envelope.ValidateChainIntegrity(chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CHAIN_BROKEN")
}

func TestChain_NonRootFirst(t *testing.T) {
	chain, _, _ := buildChain(t, 3)

	// Remove the root, making the chain start with a non-root envelope
	invalidChain := chain[1:]

	err := envelope.ValidateChainIntegrity(invalidChain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestChain_TxnIDMismatch(t *testing.T) {
	chain, _, _ := buildChain(t, 3)

	// Change txn_id on the last envelope
	chain[2].Payload.TxnID = "wrong-txn-id"

	err := envelope.ValidateChainIntegrity(chain)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "txn_id")
}

func TestDeriveEnvelope_DepthExceeded(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	now := time.Now()
	rootPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               subjectDID,
		TxnID:                    uuid.New().String(),
		CapabilityClass:          "tools",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 0, // no further delegation allowed
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}

	rootJWS, err := envelope.SignEnvelope(rootPayload, priv, issuerDID+"#key-1")
	require.NoError(t, err)

	rootToken, err := envelope.ParseToken(rootJWS)
	require.NoError(t, err)

	// Try to derive from a depth-0 envelope
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	childPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                subjectDID,
		SubjectDID:               testDID(t, nextPub),
		TxnID:                    rootPayload.TxnID,
		CapabilityClass:          "tools",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 0,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(30 * time.Minute).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}

	_, err = envelope.DeriveEnvelope(rootToken, childPayload, subPriv, subjectDID+"#key-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEPTH_EXCEEDED")
}

func TestDeriveEnvelope_NarrowingViolation(t *testing.T) {
	pub, priv := generateTestKey(t)
	issuerDID := testDID(t, pub)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	subjectDID := testDID(t, subPub)

	now := time.Now()
	rootPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               subjectDID,
		TxnID:                    uuid.New().String(),
		CapabilityClass:          "tools.database.read",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 3,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}

	rootJWS, err := envelope.SignEnvelope(rootPayload, priv, issuerDID+"#key-1")
	require.NoError(t, err)
	rootToken, err := envelope.ParseToken(rootJWS)
	require.NoError(t, err)

	// Try to derive with broader capability
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	childPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                subjectDID,
		SubjectDID:               testDID(t, nextPub),
		TxnID:                    rootPayload.TxnID,
		CapabilityClass:          "tools.database", // broader — should fail
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 2,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(30 * time.Minute).Unix(),
		IssuerBadgeJTI:           uuid.New().String(),
	}

	_, err = envelope.DeriveEnvelope(rootToken, childPayload, subPriv, subjectDID+"#key-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NARROWING")
}

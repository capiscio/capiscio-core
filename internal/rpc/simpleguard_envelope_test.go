package rpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

func newTestSimpleGuardService(t *testing.T) *SimpleGuardService {
	t.Helper()
	return NewSimpleGuardService()
}

var ctx = context.Background()

func TestCreateEnvelope_Basic(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	resp, err := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    genResp.KeyId,
		SubjectDid:               "did:key:z6MkTest",
		CapabilityClass:          "tools.database.read",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-123",
	})
	require.NoError(t, err)
	assert.Empty(t, resp.ErrorMessage)
	assert.NotEmpty(t, resp.EnvelopeJws)
	assert.NotEmpty(t, resp.EnvelopeId)

	// Verify the JWS can be parsed back
	token, err := envelope.ParseToken(resp.EnvelopeJws)
	require.NoError(t, err)
	assert.Equal(t, "tools.database.read", token.Payload.CapabilityClass)
	assert.Equal(t, 3, token.Payload.DelegationDepthRemaining)
	assert.Nil(t, token.Payload.ParentAuthorityHash) // root envelope
}

func TestDeriveEnvelope_Basic(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	parentKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})
	childKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	// Create root
	rootResp, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    parentKey.KeyId,
		SubjectDid:               childKey.DidKey,
		CapabilityClass:          "tools.database",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-parent",
	})
	require.Empty(t, rootResp.ErrorMessage)

	// Derive child
	childResp, err := svc.DeriveEnvelope(ctx, &pb.DeriveEnvelopeRequest{
		ParentEnvelopeJws:        rootResp.EnvelopeJws,
		KeyId:                    childKey.KeyId,
		SubjectDid:               "did:key:z6MkLeaf",
		CapabilityClass:          "tools.database.read", // narrower
		DelegationDepthRemaining: 1,
		SubjectBadgeJti:          "badge-child",
		IssuerBadgeJti:           "badge-child-issuer",
	})
	require.NoError(t, err)
	assert.Empty(t, childResp.ErrorMessage)
	assert.NotEmpty(t, childResp.EnvelopeJws)
	assert.NotEmpty(t, childResp.ParentAuthorityHash)
}

func TestDeriveEnvelope_NarrowingViolation(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	parentKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})
	childKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	rootResp, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    parentKey.KeyId,
		SubjectDid:               childKey.DidKey,
		CapabilityClass:          "tools.database.read", // specific
		DelegationDepthRemaining: 2,
		IssuerBadgeJti:           "badge-parent",
	})

	// Try to widen capability — should fail
	childResp, err := svc.DeriveEnvelope(ctx, &pb.DeriveEnvelopeRequest{
		ParentEnvelopeJws:        rootResp.EnvelopeJws,
		KeyId:                    childKey.KeyId,
		SubjectDid:               "did:key:z6MkLeaf",
		CapabilityClass:          "tools.database", // WIDER — violation
		DelegationDepthRemaining: 1,
		IssuerBadgeJti:           "badge-child-issuer",
	})
	require.NoError(t, err) // no Go error — app error in response
	assert.Contains(t, childResp.ErrorMessage, "narrowing")
}

func TestDeriveEnvelope_IssuerBadgeJTI_NotInherited(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	parentKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})
	childKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	rootResp, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    parentKey.KeyId,
		SubjectDid:               childKey.DidKey,
		CapabilityClass:          "tools.database",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "root-issuer-badge",
	})
	require.Empty(t, rootResp.ErrorMessage)

	childResp, err := svc.DeriveEnvelope(ctx, &pb.DeriveEnvelopeRequest{
		ParentEnvelopeJws:        rootResp.EnvelopeJws,
		KeyId:                    childKey.KeyId,
		SubjectDid:               "did:key:z6MkLeaf",
		CapabilityClass:          "tools.database.read",
		DelegationDepthRemaining: 1,
		IssuerBadgeJti:           "child-issuer-badge",
		SubjectBadgeJti:          "leaf-badge",
	})
	require.NoError(t, err)
	require.Empty(t, childResp.ErrorMessage)

	// Parse the child envelope and verify issuer badge JTI
	childToken, err := envelope.ParseToken(childResp.EnvelopeJws)
	require.NoError(t, err)
	assert.Equal(t, "child-issuer-badge", childToken.Payload.IssuerBadgeJTI,
		"child envelope must have the CHILD issuer's badge JTI, not the parent's")
	assert.NotEqual(t, "root-issuer-badge", childToken.Payload.IssuerBadgeJTI,
		"child envelope must NOT inherit the parent issuer's badge JTI")
}

func TestCreateEnvelope_SubjectBadgeJTI_Optional(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	key, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	// Without subject badge
	resp1, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    key.KeyId,
		SubjectDid:               "did:key:z6MkTest",
		CapabilityClass:          "tools.database.read",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-123",
	})
	require.Empty(t, resp1.ErrorMessage)
	token1, _ := envelope.ParseToken(resp1.EnvelopeJws)
	assert.Nil(t, token1.Payload.SubjectBadgeJTI, "SubjectBadgeJTI should be nil when not provided")

	// With subject badge
	resp2, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    key.KeyId,
		SubjectDid:               "did:key:z6MkTest",
		CapabilityClass:          "tools.database.read",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-123",
		SubjectBadgeJti:          "subject-badge-456",
	})
	require.Empty(t, resp2.ErrorMessage)
	token2, _ := envelope.ParseToken(resp2.EnvelopeJws)
	require.NotNil(t, token2.Payload.SubjectBadgeJTI)
	assert.Equal(t, "subject-badge-456", *token2.Payload.SubjectBadgeJTI)
}

func TestCreateEnvelope_EnforcementModeMin_StringType(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	key, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	// Without enforcement mode
	resp1, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    key.KeyId,
		SubjectDid:               "did:key:z6MkTest",
		CapabilityClass:          "tools.database",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-123",
	})
	require.Empty(t, resp1.ErrorMessage)
	token1, _ := envelope.ParseToken(resp1.EnvelopeJws)
	assert.Nil(t, token1.Payload.EnforcementModeMin, "should be nil when not provided")

	// With enforcement mode
	resp2, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    key.KeyId,
		SubjectDid:               "did:key:z6MkTest",
		CapabilityClass:          "tools.database",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-123",
		EnforcementModeMin:       "EM-STRICT",
	})
	require.Empty(t, resp2.ErrorMessage)
	token2, _ := envelope.ParseToken(resp2.EnvelopeJws)
	require.NotNil(t, token2.Payload.EnforcementModeMin)
	assert.Equal(t, "EM-STRICT", *token2.Payload.EnforcementModeMin)
}

func TestDeriveEnvelope_InheritsParentEnforcementMode(t *testing.T) {
	svc := newTestSimpleGuardService(t)
	parentKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})
	childKey, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519})

	rootResp, _ := svc.CreateEnvelope(ctx, &pb.CreateEnvelopeRequest{
		KeyId:                    parentKey.KeyId,
		SubjectDid:               childKey.DidKey,
		CapabilityClass:          "tools.database",
		DelegationDepthRemaining: 3,
		IssuerBadgeJti:           "badge-parent",
		EnforcementModeMin:       "EM-STRICT",
	})
	require.Empty(t, rootResp.ErrorMessage)

	// Derive child WITHOUT specifying enforcement_mode_min
	childResp, err := svc.DeriveEnvelope(ctx, &pb.DeriveEnvelopeRequest{
		ParentEnvelopeJws:        rootResp.EnvelopeJws,
		KeyId:                    childKey.KeyId,
		SubjectDid:               "did:key:z6MkLeaf",
		CapabilityClass:          "tools.database.read",
		DelegationDepthRemaining: 1,
		IssuerBadgeJti:           "badge-child",
	})
	require.NoError(t, err)
	require.Empty(t, childResp.ErrorMessage)

	childToken, err := envelope.ParseToken(childResp.EnvelopeJws)
	require.NoError(t, err)
	require.NotNil(t, childToken.Payload.EnforcementModeMin)
	assert.Equal(t, "EM-STRICT", *childToken.Payload.EnforcementModeMin,
		"child should inherit parent's enforcement_mode_min when not specified")
}

func TestBuildTransportHeaders_Encoding(t *testing.T) {
	svc := newTestSimpleGuardService(t)

	chain := []string{"eyJhbGciOiJFZERTQSJ9.root.sig", "eyJhbGciOiJFZERTQSJ9.leaf.sig"}
	badgeMap := map[string]string{"did:key:issuer": "badge-jws-1"}

	resp, err := svc.BuildTransportHeaders(ctx, &pb.BuildTransportHeadersRequest{
		Chain:    chain,
		BadgeMap: badgeMap,
	})
	require.NoError(t, err)
	assert.Empty(t, resp.ErrorMessage)
	assert.Equal(t, chain[1], resp.AuthorityHeader) // leaf
	assert.NotEmpty(t, resp.AuthorityChainHeader)
	assert.NotEmpty(t, resp.BadgeMapHeader)

	// Verify chain header can be decoded
	decoded, err := base64.RawURLEncoding.DecodeString(resp.AuthorityChainHeader)
	require.NoError(t, err)
	var decodedChain []string
	require.NoError(t, json.Unmarshal(decoded, &decodedChain))
	assert.Equal(t, chain, decodedChain)
}

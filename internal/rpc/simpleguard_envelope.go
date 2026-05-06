package rpc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// ptrIfNotEmpty returns nil if s is empty, otherwise &s.
func ptrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CreateEnvelope creates a root Authority Envelope (RFC-008 §6.1).
func (s *SimpleGuardService) CreateEnvelope(_ context.Context, req *pb.CreateEnvelopeRequest) (*pb.CreateEnvelopeResponse, error) {
	s.mu.RLock()
	entry, exists := s.keys[req.KeyId]
	s.mu.RUnlock()

	if !exists {
		return &pb.CreateEnvelopeResponse{ErrorMessage: fmt.Sprintf("key not found: %s", req.KeyId)}, nil
	}
	if entry.PrivateKey == nil {
		return &pb.CreateEnvelopeResponse{ErrorMessage: fmt.Sprintf("no private key for: %s", req.KeyId)}, nil
	}

	now := time.Now()
	expiresIn := time.Duration(req.ExpiresInSeconds) * time.Second
	if expiresIn == 0 {
		expiresIn = time.Hour
	}

	issuerDID := did.NewKeyDID(ed25519.PublicKey(entry.PublicKey))
	envelopeID := uuid.New().String()
	txnID := req.TxnId
	if txnID == "" {
		txnID = uuid.New().String()
	}

	payload := &envelope.Payload{
		EnvelopeID:               envelopeID,
		IssuerDID:                issuerDID,
		SubjectDID:               req.SubjectDid,
		TxnID:                    txnID,
		CapabilityClass:          req.CapabilityClass,
		DelegationDepthRemaining: int(req.DelegationDepthRemaining),
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(expiresIn).Unix(),
		IssuerBadgeJTI:           req.IssuerBadgeJti,
		SubjectBadgeJTI:          ptrIfNotEmpty(req.SubjectBadgeJti),
	}

	// Parse optional constraints JSON
	if req.ConstraintsJson != "" {
		var constraints map[string]any
		if err := json.Unmarshal([]byte(req.ConstraintsJson), &constraints); err != nil {
			return &pb.CreateEnvelopeResponse{ErrorMessage: fmt.Sprintf("invalid constraints JSON: %v", err)}, nil
		}
		payload.Constraints = constraints
	} else {
		payload.Constraints = map[string]any{}
	}

	// Validate and set optional enforcement mode
	if req.EnforcementModeMin != "" {
		if _, err := envelope.ParseEnforcementMode(req.EnforcementModeMin); err != nil {
			return &pb.CreateEnvelopeResponse{ErrorMessage: fmt.Sprintf("invalid enforcement mode: %v", err)}, nil
		}
		payload.EnforcementModeMin = &req.EnforcementModeMin
	}

	jws, err := envelope.SignEnvelope(payload, entry.PrivateKey, issuerDID+"#"+req.KeyId)
	if err != nil {
		return &pb.CreateEnvelopeResponse{ErrorMessage: fmt.Sprintf("sign failed: %v", err)}, nil
	}

	return &pb.CreateEnvelopeResponse{
		EnvelopeJws: jws,
		EnvelopeId:  envelopeID,
		IssuerDid:   issuerDID,
	}, nil
}

// DeriveEnvelope derives a child Authority Envelope from a parent (RFC-008 §6.3).
func (s *SimpleGuardService) DeriveEnvelope(_ context.Context, req *pb.DeriveEnvelopeRequest) (*pb.DeriveEnvelopeResponse, error) {
	s.mu.RLock()
	entry, exists := s.keys[req.KeyId]
	s.mu.RUnlock()

	if !exists {
		return &pb.DeriveEnvelopeResponse{ErrorMessage: fmt.Sprintf("key not found: %s", req.KeyId)}, nil
	}
	if entry.PrivateKey == nil {
		return &pb.DeriveEnvelopeResponse{ErrorMessage: fmt.Sprintf("no private key for: %s", req.KeyId)}, nil
	}

	// Parse parent envelope
	parent, err := envelope.ParseToken(req.ParentEnvelopeJws)
	if err != nil {
		return &pb.DeriveEnvelopeResponse{ErrorMessage: fmt.Sprintf("invalid parent envelope: %v", err)}, nil
	}

	issuerDID := did.NewKeyDID(ed25519.PublicKey(entry.PublicKey))
	now := time.Now()
	expiresIn := time.Duration(req.ExpiresInSeconds) * time.Second
	if expiresIn == 0 {
		expiresIn = 30 * time.Minute
	}

	childPayload := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                issuerDID,
		SubjectDID:               req.SubjectDid,
		TxnID:                    parent.Payload.TxnID,
		CapabilityClass:          req.CapabilityClass,
		DelegationDepthRemaining: int(req.DelegationDepthRemaining),
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(expiresIn).Unix(),
		IssuerBadgeJTI:           req.IssuerBadgeJti,
		SubjectBadgeJTI:          ptrIfNotEmpty(req.SubjectBadgeJti),
	}

	if req.ConstraintsJson != "" {
		var constraints map[string]any
		if err := json.Unmarshal([]byte(req.ConstraintsJson), &constraints); err != nil {
			return &pb.DeriveEnvelopeResponse{ErrorMessage: fmt.Sprintf("invalid constraints JSON: %v", err)}, nil
		}
		childPayload.Constraints = constraints
	} else {
		childPayload.Constraints = map[string]any{}
	}

	// Enforcement mode: inherit parent's minimum, allow escalation but not relaxation (RFC-008 §10.5)
	if req.EnforcementModeMin != "" {
		childMode, err := envelope.ParseEnforcementMode(req.EnforcementModeMin)
		if err != nil {
			return &pb.DeriveEnvelopeResponse{ErrorMessage: fmt.Sprintf("invalid enforcement mode: %v", err)}, nil
		}
		// Reject if child mode is less strict than parent's minimum
		if parent.Payload.EnforcementModeMin != nil {
			parentMode, _ := envelope.ParseEnforcementMode(*parent.Payload.EnforcementModeMin)
			if childMode < parentMode {
				return &pb.DeriveEnvelopeResponse{
					ErrorMessage: fmt.Sprintf("enforcement_mode_min %q is less strict than parent's %q; relaxation is not permitted", req.EnforcementModeMin, *parent.Payload.EnforcementModeMin),
				}, nil
			}
		}
		childPayload.EnforcementModeMin = &req.EnforcementModeMin
	} else if parent.Payload.EnforcementModeMin != nil {
		childPayload.EnforcementModeMin = parent.Payload.EnforcementModeMin
	}

	// DeriveEnvelope handles: hash linking, narrowing validation, depth check
	jws, err := envelope.DeriveEnvelope(parent, childPayload, entry.PrivateKey, issuerDID+"#"+req.KeyId)
	if err != nil {
		return &pb.DeriveEnvelopeResponse{ErrorMessage: fmt.Sprintf("derive failed: %v", err)}, nil
	}

	var parentHash string
	if childPayload.ParentAuthorityHash != nil {
		parentHash = *childPayload.ParentAuthorityHash
	}

	return &pb.DeriveEnvelopeResponse{
		EnvelopeJws:         jws,
		EnvelopeId:          childPayload.EnvelopeID,
		ParentAuthorityHash: parentHash,
	}, nil
}

// BuildTransportHeaders builds HTTP transport headers for a delegation chain (RFC-008 §15).
func (s *SimpleGuardService) BuildTransportHeaders(_ context.Context, req *pb.BuildTransportHeadersRequest) (*pb.BuildTransportHeadersResponse, error) {
	if len(req.Chain) == 0 {
		return &pb.BuildTransportHeadersResponse{ErrorMessage: "chain must not be empty"}, nil
	}

	leaf := req.Chain[len(req.Chain)-1]

	// Encode chain as base64url(JSON array)
	chainJSON, err := json.Marshal(req.Chain)
	if err != nil {
		return &pb.BuildTransportHeadersResponse{ErrorMessage: fmt.Sprintf("marshal chain: %v", err)}, nil
	}
	chainEncoded := base64.RawURLEncoding.EncodeToString(chainJSON)

	// Encode badge map as base64url(JSON object)
	var badgeMapEncoded string
	if len(req.BadgeMap) > 0 {
		bmJSON, err := json.Marshal(req.BadgeMap)
		if err != nil {
			return &pb.BuildTransportHeadersResponse{ErrorMessage: fmt.Sprintf("marshal badge map: %v", err)}, nil
		}
		badgeMapEncoded = base64.RawURLEncoding.EncodeToString(bmJSON)
	}

	return &pb.BuildTransportHeadersResponse{
		AuthorityHeader:      leaf,
		AuthorityChainHeader: chainEncoded,
		BadgeMapHeader:       badgeMapEncoded,
	}, nil
}

// VerifyEnvelopeChain verifies an Authority Envelope chain (RFC-008 §9.2).
func (s *SimpleGuardService) VerifyEnvelopeChain(ctx context.Context, req *pb.VerifyEnvelopeChainRequest) (*pb.VerifyEnvelopeChainResponse, error) {
	if len(req.Chain) == 0 {
		return &pb.VerifyEnvelopeChainResponse{
			Valid:        false,
			ErrorCode:    envelope.ErrCodeMalformed,
			ErrorMessage: "chain is empty",
		}, nil
	}

	verifier := &envelope.Verifier{
		KeyResolver: envelope.DefaultKeyResolver,
	}

	opts := envelope.VerifyOptions{
		TrustedIssuers: req.TrustedIssuers,
		// SkipBadgeVerification is true because badge verification is the
		// PEP's responsibility (it validates the caller's badge separately).
		// Chain verification only validates envelope signatures and structure.
		SkipBadgeVerification: true,
	}

	if req.EnforcementMode != "" {
		em, err := envelope.ParseEnforcementMode(req.EnforcementMode)
		if err != nil {
			return &pb.VerifyEnvelopeChainResponse{
				Valid:        false,
				ErrorCode:    envelope.ErrCodeMalformed,
				ErrorMessage: fmt.Sprintf("invalid enforcement_mode: %v", err),
			}, nil
		}
		opts.EnforcementMode = em
	}

	result, err := verifier.VerifyChain(ctx, req.Chain, req.BadgeMap, opts)
	if err != nil {
		var envErr *envelope.Error
		if errors.As(err, &envErr) {
			return &pb.VerifyEnvelopeChainResponse{
				Valid:        false,
				ErrorCode:    envErr.Code,
				ErrorMessage: envErr.Message,
			}, nil
		}
		return &pb.VerifyEnvelopeChainResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("verification failed: %v", err),
		}, nil
	}

	// Extract leaf info
	var leafIssuerDID, leafSubjectDID string
	if len(result.Links) > 0 {
		leafLink := result.Links[len(result.Links)-1]
		leafIssuerDID = leafLink.Payload.IssuerDID
		leafSubjectDID = leafLink.Payload.SubjectDID
	}

	return &pb.VerifyEnvelopeChainResponse{
		Valid:          true,
		RootCapability: result.RootCapability,
		LeafCapability: result.LeafCapability,
		TotalDepth:     int32(result.TotalDepth),
		LeafIssuerDid:  leafIssuerDID,
		LeafSubjectDid: leafSubjectDID,
	}, nil
}

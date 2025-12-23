package rpc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"

	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// BadgeService implements the gRPC BadgeService.
type BadgeService struct {
	pb.UnimplementedBadgeServiceServer
}

// NewBadgeService creates a new BadgeService instance.
func NewBadgeService() *BadgeService {
	return &BadgeService{}
}

// SignBadge signs a new badge with the provided claims.
func (s *BadgeService) SignBadge(_ context.Context, req *pb.SignBadgeRequest) (*pb.SignBadgeResponse, error) {
	if req.Claims == nil {
		return &pb.SignBadgeResponse{}, fmt.Errorf("claims are required")
	}

	// Convert protobuf claims to badge.Claims
	claims := protoToBadgeClaims(req.Claims)

	// Parse private key from JWK
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(req.PrivateKeyJwk), &jwk); err != nil {
		return &pb.SignBadgeResponse{}, fmt.Errorf("failed to parse private key JWK: %w", err)
	}

	// Extract the private key
	privateKey, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return &pb.SignBadgeResponse{}, fmt.Errorf("expected Ed25519 private key")
	}

	// Sign the badge
	token, err := badge.SignBadge(claims, privateKey)
	if err != nil {
		return &pb.SignBadgeResponse{}, fmt.Errorf("failed to sign badge: %w", err)
	}

	return &pb.SignBadgeResponse{
		Token:  token,
		Claims: req.Claims,
	}, nil
}

// VerifyBadge verifies a badge token (basic verification).
func (s *BadgeService) VerifyBadge(_ context.Context, req *pb.VerifyBadgeRequest) (*pb.VerifyBadgeResponse, error) {
	if req.Token == "" {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "INVALID_INPUT",
			ErrorMessage: "token is required",
		}, nil
	}

	// Parse the JWS to extract claims
	jwsObj, err := jose.ParseSigned(req.Token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "MALFORMED",
			ErrorMessage: fmt.Sprintf("failed to parse JWS: %v", err),
		}, nil
	}

	// If public key is provided, verify with it
	if req.PublicKeyJwk != "" {
		var jwk jose.JSONWebKey
		if err := json.Unmarshal([]byte(req.PublicKeyJwk), &jwk); err != nil {
			return &pb.VerifyBadgeResponse{
				Valid:        false,
				ErrorCode:    "INVALID_KEY",
				ErrorMessage: fmt.Sprintf("failed to parse public key JWK: %v", err),
			}, nil
		}

		payload, err := jwsObj.Verify(jwk.Key)
		if err != nil {
			return &pb.VerifyBadgeResponse{
				Valid:        false,
				ErrorCode:    "SIGNATURE_INVALID",
				ErrorMessage: fmt.Sprintf("signature verification failed: %v", err),
			}, nil
		}

		// Parse verified claims
		var claims badge.Claims
		if err := json.Unmarshal(payload, &claims); err != nil {
			return &pb.VerifyBadgeResponse{
				Valid:        false,
				ErrorCode:    "MALFORMED",
				ErrorMessage: fmt.Sprintf("failed to parse claims: %v", err),
			}, nil
		}

		return &pb.VerifyBadgeResponse{
			Valid:    true,
			Claims:   badgeClaimsToProto(&claims),
			ModeUsed: pb.VerifyMode_VERIFY_MODE_OFFLINE,
		}, nil
	}

	// Without a public key, we can only parse (not verify)
	return &pb.VerifyBadgeResponse{
		Valid:        false,
		ErrorCode:    "MISSING_KEY",
		ErrorMessage: "public key required for verification",
	}, nil
}

// parseJWSToken parses a JWS token and extracts claims.
func (s *BadgeService) parseJWSToken(token string) (*jose.JSONWebSignature, *badge.Claims, error) {
	jwsObj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	payload := jwsObj.UnsafePayloadWithoutVerification()
	var claims badge.Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return jwsObj, &claims, nil
}

// buildVerifyOptions constructs verification options from the request.
func (s *BadgeService) buildVerifyOptions(req *pb.VerifyBadgeWithOptionsRequest) badge.VerifyOptions {
	// Return defaults when no options provided
	if req.Options == nil {
		return badge.VerifyOptions{
			Mode:                 badge.VerifyModeOnline,
			SkipRevocationCheck:  true,
			SkipAgentStatusCheck: true,
		}
	}

	// Build options from request
	opts := badge.VerifyOptions{
		TrustedIssuers:       req.Options.TrustedIssuers,
		Audience:             req.Options.Audience,
		SkipRevocationCheck:  req.Options.SkipRevocation,
		SkipAgentStatusCheck: req.Options.SkipAgentStatus,
		AcceptSelfSigned:     req.Options.AcceptSelfSigned,
	}

	// Map verify mode from proto enum
	switch req.Options.Mode {
	case pb.VerifyMode_VERIFY_MODE_OFFLINE:
		opts.Mode = badge.VerifyModeOffline
	case pb.VerifyMode_VERIFY_MODE_HYBRID:
		opts.Mode = badge.VerifyModeHybrid
	default:
		opts.Mode = badge.VerifyModeOnline
	}

	return opts
}

// verifySelfSignedBadge verifies a self-signed badge with did:key issuer.
func (s *BadgeService) verifySelfSignedBadge(jwsObj *jose.JSONWebSignature, claims *badge.Claims, opts badge.VerifyOptions) (*pb.VerifyBadgeResponse, error) {
	// Check if self-signed badges are accepted
	if !opts.AcceptSelfSigned {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "SELF_SIGNED_NOT_ACCEPTED",
			ErrorMessage: "self-signed badges (did:key issuer) require accept_self_signed option",
		}, nil
	}

	// Extract public key from did:key
	pubKey, err := did.PublicKeyFromKeyDID(claims.Issuer)
	if err != nil {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "INVALID_ISSUER",
			ErrorMessage: fmt.Sprintf("failed to extract public key from did:key: %v", err),
		}, nil
	}

	// Verify signature
	verifiedPayload, err := jwsObj.Verify(pubKey)
	if err != nil {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "SIGNATURE_INVALID",
			ErrorMessage: fmt.Sprintf("signature verification failed: %v", err),
		}, nil
	}

	// Re-parse verified claims
	var verifiedClaims badge.Claims
	if err := json.Unmarshal(verifiedPayload, &verifiedClaims); err != nil {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "MALFORMED",
			ErrorMessage: fmt.Sprintf("failed to parse verified claims: %v", err),
		}, nil
	}

	// Validate self-signed constraints
	if resp := s.validateSelfSignedConstraints(&verifiedClaims, opts); resp != nil {
		return resp, nil
	}

	warnings := []string{
		"self-signed badge (did:key issuer)",
		"revocation check skipped (self-signed badge)",
		"agent status check skipped (self-signed badge)",
	}

	return &pb.VerifyBadgeResponse{
		Valid:    true,
		Claims:   badgeClaimsToProto(&verifiedClaims),
		ModeUsed: pb.VerifyMode_VERIFY_MODE_OFFLINE,
		Warnings: warnings,
	}, nil
}

// validateSelfSignedConstraints checks self-signed badge constraints.
func (s *BadgeService) validateSelfSignedConstraints(claims *badge.Claims, opts badge.VerifyOptions) *pb.VerifyBadgeResponse {
	// Validate iss == sub
	if claims.Issuer != claims.Subject {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "SELF_SIGNED_INVALID",
			ErrorMessage: "self-signed badge must have iss == sub",
		}
	}

	// Validate trust level is 0
	if claims.TrustLevel() != "0" {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "SELF_SIGNED_INVALID",
			ErrorMessage: fmt.Sprintf("self-signed badge must be trust level 0, got %s", claims.TrustLevel()),
		}
	}

	// Check expiry
	if claims.IsExpired() {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "EXPIRED",
			ErrorMessage: "badge has expired",
		}
	}

	// Check not yet valid
	if claims.IsNotYetValid() {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "NOT_YET_VALID",
			ErrorMessage: "badge is not yet valid",
		}
	}

	// Check audience
	if opts.Audience != "" && len(claims.Audience) > 0 {
		found := false
		for _, aud := range claims.Audience {
			if aud == opts.Audience {
				found = true
				break
			}
		}
		if !found {
			return &pb.VerifyBadgeResponse{
				Valid:        false,
				ErrorCode:    "AUDIENCE_MISMATCH",
				ErrorMessage: fmt.Sprintf("audience %s not in allowed list", opts.Audience),
			}
		}
	}

	return nil
}

// VerifyBadgeWithOptions performs badge verification with full options.
func (s *BadgeService) VerifyBadgeWithOptions(_ context.Context, req *pb.VerifyBadgeWithOptionsRequest) (*pb.VerifyBadgeResponse, error) {
	if req.Token == "" {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "INVALID_INPUT",
			ErrorMessage: "token is required",
		}, nil
	}

	// Parse JWS and extract claims
	jwsObj, claims, err := s.parseJWSToken(req.Token)
	if err != nil {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "MALFORMED",
			ErrorMessage: err.Error(),
		}, nil
	}

	// Build verification options
	opts := s.buildVerifyOptions(req)

	// Check if this is a self-signed badge (did:key issuer)
	if strings.HasPrefix(claims.Issuer, "did:key:") {
		return s.verifySelfSignedBadge(jwsObj, claims, opts)
	}

	// For did:web issuers, we need a registry or public key
	return &pb.VerifyBadgeResponse{
		Valid:        false,
		ErrorCode:    "REGISTRY_NOT_CONFIGURED",
		ErrorMessage: "registry-backed verification not yet available via RPC; use --key flag with CLI or provide public_key_jwk",
	}, nil
}

// ParseBadge parses badge claims without verification.
func (s *BadgeService) ParseBadge(_ context.Context, req *pb.ParseBadgeRequest) (*pb.ParseBadgeResponse, error) {
	if req.Token == "" {
		return &pb.ParseBadgeResponse{
			ErrorMessage: "token is required",
		}, nil
	}

	// Parse the JWS
	jwsObj, err := jose.ParseSigned(req.Token, []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256})
	if err != nil {
		return &pb.ParseBadgeResponse{
			ErrorMessage: fmt.Sprintf("failed to parse JWS: %v", err),
		}, nil
	}

	// Extract claims without verification
	payload := jwsObj.UnsafePayloadWithoutVerification()
	var claims badge.Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return &pb.ParseBadgeResponse{
			ErrorMessage: fmt.Sprintf("failed to parse claims: %v", err),
		}, nil
	}

	return &pb.ParseBadgeResponse{
		Claims: badgeClaimsToProto(&claims),
	}, nil
}

// Helper functions for conversion between proto and badge types

func protoToBadgeClaims(pb *pb.BadgeClaims) *badge.Claims {
	if pb == nil {
		return nil
	}
	return &badge.Claims{
		JTI:      pb.Jti,
		Issuer:   pb.Iss,
		Subject:  pb.Sub,
		IssuedAt: pb.Iat,
		Expiry:   pb.Exp,
		Audience: pb.Aud,
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: pb.Domain,
				Level:  trustLevelToString(pb.TrustLevel),
			},
		},
	}
}

func badgeClaimsToProto(c *badge.Claims) *pb.BadgeClaims {
	if c == nil {
		return nil
	}
	return &pb.BadgeClaims{
		Jti:        c.JTI,
		Iss:        c.Issuer,
		Sub:        c.Subject,
		Iat:        c.IssuedAt,
		Exp:        c.Expiry,
		Aud:        c.Audience,
		TrustLevel: stringToTrustLevel(c.TrustLevel()),
		Domain:     c.Domain(),
		AgentName:  c.AgentID(),
	}
}

func trustLevelToString(tl pb.TrustLevel) string {
	switch tl {
	case pb.TrustLevel_TRUST_LEVEL_SELF_SIGNED:
		return "0"
	case pb.TrustLevel_TRUST_LEVEL_DV:
		return "1"
	case pb.TrustLevel_TRUST_LEVEL_OV:
		return "2"
	case pb.TrustLevel_TRUST_LEVEL_EV:
		return "3"
	case pb.TrustLevel_TRUST_LEVEL_CV:
		return "4"
	default:
		return ""
	}
}

func stringToTrustLevel(s string) pb.TrustLevel {
	switch s {
	case "0":
		return pb.TrustLevel_TRUST_LEVEL_SELF_SIGNED
	case "1":
		return pb.TrustLevel_TRUST_LEVEL_DV
	case "2":
		return pb.TrustLevel_TRUST_LEVEL_OV
	case "3":
		return pb.TrustLevel_TRUST_LEVEL_EV
	case "4":
		return pb.TrustLevel_TRUST_LEVEL_CV
	default:
		return pb.TrustLevel_TRUST_LEVEL_UNSPECIFIED
	}
}

// RequestBadge requests a new badge from a Certificate Authority (RFC-002 §12.1).
func (s *BadgeService) RequestBadge(ctx context.Context, req *pb.RequestBadgeRequest) (*pb.RequestBadgeResponse, error) {
	if req.AgentId == "" {
		return &pb.RequestBadgeResponse{
			Success:   false,
			Error:     "agent_id is required",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	if req.ApiKey == "" {
		return &pb.RequestBadgeResponse{
			Success:   false,
			Error:     "api_key is required for CA mode",
			ErrorCode: "AUTH_REQUIRED",
		}, nil
	}

	// Build options
	caURL := req.CaUrl
	if caURL == "" {
		caURL = badge.DefaultCAURL
	}

	ttl := time.Duration(req.TtlSeconds) * time.Second
	if ttl == 0 {
		ttl = badge.DefaultTTL
	}

	opts := badge.RequestBadgeOptions{
		AgentID:    req.AgentId,
		Domain:     req.Domain,
		TTL:        ttl,
		TrustLevel: trustLevelToString(req.TrustLevel),
		Audience:   req.Audience,
	}

	// Create client and request badge
	client := badge.NewClient(caURL, req.ApiKey)
	result, err := client.RequestBadge(ctx, opts)
	if err != nil {
		// Check for specific error types
		if clientErr, ok := err.(*badge.ClientError); ok {
			return &pb.RequestBadgeResponse{
				Success:   false,
				Error:     clientErr.Message,
				ErrorCode: clientErr.Code,
			}, nil
		}
		return &pb.RequestBadgeResponse{
			Success:   false,
			Error:     err.Error(),
			ErrorCode: "CA_ERROR",
		}, nil
	}

	return &pb.RequestBadgeResponse{
		Success:    true,
		Token:      result.Token,
		Jti:        result.JTI,
		Subject:    result.Subject,
		TrustLevel: stringToTrustLevel(result.TrustLevel),
		ExpiresAt:  result.ExpiresAt.Unix(),
	}, nil
}

// RequestPoPBadge requests a badge using Proof of Possession (RFC-003).
func (s *BadgeService) RequestPoPBadge(ctx context.Context, req *pb.RequestPoPBadgeRequest) (*pb.RequestPoPBadgeResponse, error) {
	if req.AgentDid == "" {
		return &pb.RequestPoPBadgeResponse{
			Success:   false,
			Error:     "agent_did is required",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	if req.PrivateKeyJwk == "" {
		return &pb.RequestPoPBadgeResponse{
			Success:   false,
			Error:     "private_key_jwk is required for PoP",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	if req.ApiKey == "" {
		return &pb.RequestPoPBadgeResponse{
			Success:   false,
			Error:     "api_key is required",
			ErrorCode: "AUTH_REQUIRED",
		}, nil
	}

	// Parse private key from JWK
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(req.PrivateKeyJwk), &jwk); err != nil {
		return &pb.RequestPoPBadgeResponse{
			Success:   false,
			Error:     fmt.Sprintf("failed to parse private key JWK: %v", err),
			ErrorCode: "INVALID_KEY",
		}, nil
	}

	// Extract the private key
	privateKey, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return &pb.RequestPoPBadgeResponse{
			Success:   false,
			Error:     "expected Ed25519 private key",
			ErrorCode: "INVALID_KEY",
		}, nil
	}

	// Build options
	caURL := req.CaUrl
	if caURL == "" {
		caURL = badge.DefaultCAURL
	}

	ttl := time.Duration(req.TtlSeconds) * time.Second
	if ttl == 0 {
		ttl = badge.DefaultTTL
	}

	opts := badge.RequestPoPBadgeOptions{
		AgentDID:   req.AgentDid,
		PrivateKey: privateKey,
		TTL:        ttl,
		Audience:   req.Audience,
	}

	// Create PoP client and request badge
	client := badge.NewPoPClient(caURL, req.ApiKey)
	result, err := client.RequestPoPBadge(ctx, opts)
	if err != nil {
		// Check for specific error types
		if clientErr, ok := err.(*badge.ClientError); ok {
			return &pb.RequestPoPBadgeResponse{
				Success:   false,
				Error:     clientErr.Message,
				ErrorCode: clientErr.Code,
			}, nil
		}
		return &pb.RequestPoPBadgeResponse{
			Success:   false,
			Error:     err.Error(),
			ErrorCode: "CA_ERROR",
		}, nil
	}

	// Convert CNF map to proto map
	cnfMap := make(map[string]string)
	for k, v := range result.CNF {
		cnfMap[k] = fmt.Sprintf("%v", v)
	}

	return &pb.RequestPoPBadgeResponse{
		Success:        true,
		Token:          result.Token,
		Jti:            result.JTI,
		Subject:        result.Subject,
		TrustLevel:     result.TrustLevel,
		AssuranceLevel: result.AssuranceLevel,
		ExpiresAt:      result.ExpiresAt.Unix(),
		Cnf:            cnfMap,
	}, nil
}

// validateKeeperRequest validates the keeper request parameters.
func (s *BadgeService) validateKeeperRequest(req *pb.StartKeeperRequest) error {
	switch req.Mode {
	case pb.KeeperMode_KEEPER_MODE_CA:
		if req.AgentId == "" {
			return fmt.Errorf("agent_id is required for CA mode")
		}
		if req.ApiKey == "" {
			return fmt.Errorf("api_key is required for CA mode")
		}
	case pb.KeeperMode_KEEPER_MODE_SELF_SIGN:
		if req.PrivateKeyPath == "" {
			return fmt.Errorf("private_key_path is required for self-sign mode")
		}
	default:
		return fmt.Errorf("mode must be CA or SELF_SIGN")
	}
	return nil
}

// buildKeeperConfig builds the base keeper configuration from request.
func (s *BadgeService) buildKeeperConfig(req *pb.StartKeeperRequest) badge.KeeperConfig {
	config := badge.KeeperConfig{
		OutputFile: req.OutputFile,
		Domain:     req.Domain,
		TrustLevel: trustLevelToString(req.TrustLevel),
	}

	// Set durations with defaults
	config.Expiry = 5 * time.Minute
	if req.TtlSeconds > 0 {
		config.Expiry = time.Duration(req.TtlSeconds) * time.Second
	}

	config.RenewBefore = 1 * time.Minute
	if req.RenewBeforeSeconds > 0 {
		config.RenewBefore = time.Duration(req.RenewBeforeSeconds) * time.Second
	}

	config.CheckInterval = 30 * time.Second
	if req.CheckIntervalSeconds > 0 {
		config.CheckInterval = time.Duration(req.CheckIntervalSeconds) * time.Second
	}

	return config
}

// configureCAMode configures the keeper for CA mode.
func (s *BadgeService) configureCAMode(config *badge.KeeperConfig, req *pb.StartKeeperRequest) {
	config.Mode = badge.KeeperModeCA
	config.CAURL = req.CaUrl
	if config.CAURL == "" {
		config.CAURL = badge.DefaultCAURL
	}
	config.APIKey = req.ApiKey
	config.AgentID = req.AgentId
}

// configureSelfSignMode configures the keeper for self-sign mode.
func (s *BadgeService) configureSelfSignMode(config *badge.KeeperConfig, req *pb.StartKeeperRequest) error {
	config.Mode = badge.KeeperModeSelfSign
	config.TrustLevel = "0" // Self-sign is always level 0

	// Load private key
	keyData, err := os.ReadFile(req.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keyData, &jwk); err != nil {
		return fmt.Errorf("failed to parse private key JWK: %w", err)
	}

	priv, ok := jwk.Key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("expected Ed25519 private key")
	}

	config.PrivateKey = priv

	// Generate did:key for self-signed mode
	pub := priv.Public().(ed25519.PublicKey)
	didKey := did.NewKeyDID(pub)

	pubJWK := &jose.JSONWebKey{
		Key:       pub,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	config.Claims = badge.Claims{
		Issuer:  didKey,
		Subject: didKey,
		Key:     pubJWK,
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: req.Domain,
				Level:  "0",
			},
		},
	}

	return nil
}

// StartKeeper starts a badge keeper daemon that automatically renews badges (RFC-002 §7.3).
func (s *BadgeService) StartKeeper(req *pb.StartKeeperRequest, stream pb.BadgeService_StartKeeperServer) error {
	// Validate request
	if err := s.validateKeeperRequest(req); err != nil {
		return err
	}

	// Build base keeper config
	config := s.buildKeeperConfig(req)

	// Configure mode-specific settings
	if req.Mode == pb.KeeperMode_KEEPER_MODE_CA {
		s.configureCAMode(&config, req)
	} else {
		if err := s.configureSelfSignMode(&config, req); err != nil {
			return err
		}
	}

	// Create keeper
	keeper, err := badge.NewKeeper(config)
	if err != nil {
		return err
	}

	// Create event channel
	events := make(chan badge.KeeperEvent, 10)

	// Start keeper in goroutine
	ctx := stream.Context()
	go func() {
		_ = keeper.RunWithEvents(ctx, events)
	}()

	// Stream events to client
	for event := range events {
		pbEvent := &pb.KeeperEvent{
			Type:       keeperEventTypeToPB(event.Type),
			BadgeJti:   event.BadgeJTI,
			Subject:    event.Subject,
			TrustLevel: stringToTrustLevel(event.TrustLevel),
			ExpiresAt:  event.ExpiresAt.Unix(),
			Error:      event.Error,
			ErrorCode:  event.ErrorCode,
			Timestamp:  event.Timestamp.Unix(),
			Token:      event.Token,
		}

		if err := stream.Send(pbEvent); err != nil {
			return err
		}
	}

	return nil
}

func keeperEventTypeToPB(t badge.KeeperEventType) pb.KeeperEventType {
	switch t {
	case badge.KeeperEventStarted:
		return pb.KeeperEventType_KEEPER_EVENT_STARTED
	case badge.KeeperEventRenewed:
		return pb.KeeperEventType_KEEPER_EVENT_RENEWED
	case badge.KeeperEventError:
		return pb.KeeperEventType_KEEPER_EVENT_ERROR
	case badge.KeeperEventStopped:
		return pb.KeeperEventType_KEEPER_EVENT_STOPPED
	default:
		return pb.KeeperEventType_KEEPER_EVENT_UNSPECIFIED
	}
}

// ============================================================================
// Domain Validated (DV) Badge Orders (RFC-002 v1.2)
// ============================================================================

// CreateDVOrder creates a new DV badge order.
func (s *BadgeService) CreateDVOrder(ctx context.Context, req *pb.CreateDVOrderRequest) (*pb.CreateDVOrderResponse, error) {
	if req.Domain == "" {
		return &pb.CreateDVOrderResponse{
			Success:   false,
			Error:     "domain is required",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	if req.ChallengeType != "http-01" && req.ChallengeType != "dns-01" {
		return &pb.CreateDVOrderResponse{
			Success:   false,
			Error:     fmt.Sprintf("invalid challenge_type: %s (must be 'http-01' or 'dns-01')", req.ChallengeType),
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	if req.Jwk == "" {
		return &pb.CreateDVOrderResponse{
			Success:   false,
			Error:     "jwk is required",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	// Parse JWK
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(req.Jwk), &jwk); err != nil {
		return &pb.CreateDVOrderResponse{
			Success:   false,
			Error:     fmt.Sprintf("failed to parse JWK: %v", err),
			ErrorCode: "INVALID_KEY",
		}, nil
	}

	// Make HTTP request to server
	caURL := req.CaUrl
	if caURL == "" {
		caURL = badge.DefaultCAURL
	}

	client := badge.NewDVClient(caURL)
	order, err := client.CreateOrder(ctx, req.Domain, req.ChallengeType, &jwk)
	if err != nil {
		return &pb.CreateDVOrderResponse{
			Success:   false,
			Error:     err.Error(),
			ErrorCode: "CA_ERROR",
		}, nil
	}

	return &pb.CreateDVOrderResponse{
		Success:        true,
		OrderId:        order.ID,
		Domain:         order.Domain,
		ChallengeType:  order.ChallengeType,
		ChallengeToken: order.ChallengeToken,
		Status:         order.Status,
		ValidationUrl:  order.ValidationURL,
		DnsRecord:      order.DNSRecord,
		ExpiresAt:      order.ExpiresAt.Unix(),
	}, nil
}

// GetDVOrder gets the status of a DV badge order.
func (s *BadgeService) GetDVOrder(ctx context.Context, req *pb.GetDVOrderRequest) (*pb.GetDVOrderResponse, error) {
	if req.OrderId == "" {
		return &pb.GetDVOrderResponse{
			Success:   false,
			Error:     "order_id is required",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	// Make HTTP request to server
	caURL := req.CaUrl
	if caURL == "" {
		caURL = badge.DefaultCAURL
	}

	client := badge.NewDVClient(caURL)
	order, err := client.GetOrder(ctx, req.OrderId)
	if err != nil {
		return &pb.GetDVOrderResponse{
			Success:   false,
			Error:     err.Error(),
			ErrorCode: "CA_ERROR",
		}, nil
	}

	resp := &pb.GetDVOrderResponse{
		Success:        true,
		OrderId:        order.ID,
		Domain:         order.Domain,
		ChallengeType:  order.ChallengeType,
		ChallengeToken: order.ChallengeToken,
		Status:         order.Status,
		ValidationUrl:  order.ValidationURL,
		DnsRecord:      order.DNSRecord,
		ExpiresAt:      order.ExpiresAt.Unix(),
	}

	if order.FinalizedAt != nil {
		resp.FinalizedAt = order.FinalizedAt.Unix()
	}

	return resp, nil
}

// FinalizeDVOrder finalizes a DV badge order and receives a grant.
func (s *BadgeService) FinalizeDVOrder(ctx context.Context, req *pb.FinalizeDVOrderRequest) (*pb.FinalizeDVOrderResponse, error) {
	if req.OrderId == "" {
		return &pb.FinalizeDVOrderResponse{
			Success:   false,
			Error:     "order_id is required",
			ErrorCode: "INVALID_INPUT",
		}, nil
	}

	// Make HTTP request to server
	caURL := req.CaUrl
	if caURL == "" {
		caURL = badge.DefaultCAURL
	}

	client := badge.NewDVClient(caURL)
	grant, err := client.FinalizeOrder(ctx, req.OrderId)
	if err != nil {
		return &pb.FinalizeDVOrderResponse{
			Success:   false,
			Error:     err.Error(),
			ErrorCode: "CA_ERROR",
		}, nil
	}

	return &pb.FinalizeDVOrderResponse{
		Success:   true,
		Grant:     grant.Grant,
		ExpiresAt: grant.ExpiresAt.Unix(),
	}, nil
}

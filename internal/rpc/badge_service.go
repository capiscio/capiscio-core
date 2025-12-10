package rpc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/go-jose/go-jose/v4"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
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
func (s *BadgeService) SignBadge(ctx context.Context, req *pb.SignBadgeRequest) (*pb.SignBadgeResponse, error) {
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
func (s *BadgeService) VerifyBadge(ctx context.Context, req *pb.VerifyBadgeRequest) (*pb.VerifyBadgeResponse, error) {
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

// VerifyBadgeWithOptions performs badge verification with full options.
func (s *BadgeService) VerifyBadgeWithOptions(ctx context.Context, req *pb.VerifyBadgeWithOptionsRequest) (*pb.VerifyBadgeResponse, error) {
	if req.Token == "" {
		return &pb.VerifyBadgeResponse{
			Valid:        false,
			ErrorCode:    "INVALID_INPUT",
			ErrorMessage: "token is required",
		}, nil
	}

	// TODO: Implement full verification with registry integration
	// For now, return unimplemented
	return &pb.VerifyBadgeResponse{
		Valid:        false,
		ErrorCode:    "UNIMPLEMENTED",
		ErrorMessage: "full verification with options not yet implemented",
	}, nil
}

// ParseBadge parses badge claims without verification.
func (s *BadgeService) ParseBadge(ctx context.Context, req *pb.ParseBadgeRequest) (*pb.ParseBadgeResponse, error) {
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
	case pb.TrustLevel_TRUST_LEVEL_DV:
		return "1"
	case pb.TrustLevel_TRUST_LEVEL_OV:
		return "2"
	case pb.TrustLevel_TRUST_LEVEL_EV:
		return "3"
	default:
		return ""
	}
}

func stringToTrustLevel(s string) pb.TrustLevel {
	switch s {
	case "1":
		return pb.TrustLevel_TRUST_LEVEL_DV
	case "2":
		return pb.TrustLevel_TRUST_LEVEL_OV
	case "3":
		return pb.TrustLevel_TRUST_LEVEL_EV
	default:
		return pb.TrustLevel_TRUST_LEVEL_UNSPECIFIED
	}
}

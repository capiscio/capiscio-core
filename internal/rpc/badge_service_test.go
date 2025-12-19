package rpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/did"
	"github.com/go-jose/go-jose/v4"

	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

func TestNewBadgeService(t *testing.T) {
	svc := NewBadgeService()
	if svc == nil {
		t.Fatal("NewBadgeService returned nil")
	}
}

func TestBadgeService_SignBadge(t *testing.T) {
	svc := NewBadgeService()
	ctx := context.Background()

	// Generate test key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWK
	jwk := jose.JSONWebKey{
		Key:       priv,
		Algorithm: string(jose.EdDSA),
	}
	jwkBytes, _ := json.Marshal(jwk)

	didKey := did.NewKeyDID(pub)

	tests := []struct {
		name      string
		req       *pb.SignBadgeRequest
		wantErr   bool
		wantToken bool
	}{
		{
			name:    "nil claims",
			req:     &pb.SignBadgeRequest{Claims: nil},
			wantErr: true,
		},
		{
			name: "invalid JWK",
			req: &pb.SignBadgeRequest{
				Claims:        &pb.BadgeClaims{Jti: "test", Iss: didKey, Sub: didKey},
				PrivateKeyJwk: "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid request",
			req: &pb.SignBadgeRequest{
				Claims: &pb.BadgeClaims{
					Jti:        "test-jti",
					Iss:        didKey,
					Sub:        didKey,
					Iat:        time.Now().Unix(),
					Exp:        time.Now().Add(5 * time.Minute).Unix(),
					TrustLevel: pb.TrustLevel_TRUST_LEVEL_SELF_SIGNED,
				},
				PrivateKeyJwk: string(jwkBytes),
			},
			wantToken: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.SignBadge(ctx, tt.req)
			if tt.wantErr {
				if err == nil && resp.Token != "" {
					t.Errorf("expected error but got token")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantToken && resp.Token == "" {
				t.Error("expected token but got empty")
			}
		})
	}
}

func TestBadgeService_VerifyBadge(t *testing.T) {
	svc := NewBadgeService()
	ctx := context.Background()

	// Generate test key pair and create a badge
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	didKey := did.NewKeyDID(pub)

	claims := &badge.Claims{
		JTI:      "test-jti",
		Issuer:   didKey,
		Subject:  didKey,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(5 * time.Minute).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Level: "0",
			},
		},
	}
	token, _ := badge.SignBadge(claims, priv)

	pubJWK := jose.JSONWebKey{Key: pub, Algorithm: string(jose.EdDSA)}
	pubJWKBytes, _ := json.Marshal(pubJWK)

	tests := []struct {
		name      string
		req       *pb.VerifyBadgeRequest
		wantValid bool
		wantCode  string
	}{
		{
			name:      "empty token",
			req:       &pb.VerifyBadgeRequest{Token: ""},
			wantValid: false,
			wantCode:  "INVALID_INPUT",
		},
		{
			name:      "malformed token",
			req:       &pb.VerifyBadgeRequest{Token: "not-a-jws"},
			wantValid: false,
			wantCode:  "MALFORMED",
		},
		{
			name:      "no public key",
			req:       &pb.VerifyBadgeRequest{Token: token},
			wantValid: false,
			wantCode:  "MISSING_KEY",
		},
		{
			name:      "invalid public key",
			req:       &pb.VerifyBadgeRequest{Token: token, PublicKeyJwk: "invalid"},
			wantValid: false,
			wantCode:  "INVALID_KEY",
		},
		{
			name:      "valid verification",
			req:       &pb.VerifyBadgeRequest{Token: token, PublicKeyJwk: string(pubJWKBytes)},
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.VerifyBadge(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Valid != tt.wantValid {
				t.Errorf("valid = %v, want %v", resp.Valid, tt.wantValid)
			}
			if tt.wantCode != "" && resp.ErrorCode != tt.wantCode {
				t.Errorf("errorCode = %v, want %v", resp.ErrorCode, tt.wantCode)
			}
		})
	}
}

func TestBadgeService_VerifyBadgeWithOptions(t *testing.T) {
	svc := NewBadgeService()
	ctx := context.Background()

	// Generate self-signed badge
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	didKey := did.NewKeyDID(pub)

	claims := &badge.Claims{
		JTI:      "test-jti",
		Issuer:   didKey,
		Subject:  didKey,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(5 * time.Minute).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Level: "0",
			},
		},
	}
	token, _ := badge.SignBadge(claims, priv)

	tests := []struct {
		name      string
		req       *pb.VerifyBadgeWithOptionsRequest
		wantValid bool
		wantCode  string
	}{
		{
			name:      "empty token",
			req:       &pb.VerifyBadgeWithOptionsRequest{Token: ""},
			wantValid: false,
			wantCode:  "INVALID_INPUT",
		},
		{
			name:      "malformed token",
			req:       &pb.VerifyBadgeWithOptionsRequest{Token: "not-a-jws"},
			wantValid: false,
			wantCode:  "MALFORMED",
		},
		{
			name: "self-signed not accepted",
			req: &pb.VerifyBadgeWithOptionsRequest{
				Token:   token,
				Options: &pb.VerifyOptions{AcceptSelfSigned: false},
			},
			wantValid: false,
			wantCode:  "SELF_SIGNED_NOT_ACCEPTED",
		},
		{
			name: "self-signed accepted",
			req: &pb.VerifyBadgeWithOptionsRequest{
				Token:   token,
				Options: &pb.VerifyOptions{AcceptSelfSigned: true},
			},
			wantValid: true,
		},
		{
			name: "with verify mode offline",
			req: &pb.VerifyBadgeWithOptionsRequest{
				Token: token,
				Options: &pb.VerifyOptions{
					AcceptSelfSigned: true,
					Mode:             pb.VerifyMode_VERIFY_MODE_OFFLINE,
				},
			},
			wantValid: true,
		},
		{
			name: "with verify mode hybrid",
			req: &pb.VerifyBadgeWithOptionsRequest{
				Token: token,
				Options: &pb.VerifyOptions{
					AcceptSelfSigned: true,
					Mode:             pb.VerifyMode_VERIFY_MODE_HYBRID,
				},
			},
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.VerifyBadgeWithOptions(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Valid != tt.wantValid {
				t.Errorf("valid = %v, want %v (code: %s, msg: %s)", resp.Valid, tt.wantValid, resp.ErrorCode, resp.ErrorMessage)
			}
			if tt.wantCode != "" && resp.ErrorCode != tt.wantCode {
				t.Errorf("errorCode = %v, want %v", resp.ErrorCode, tt.wantCode)
			}
		})
	}
}

func TestBadgeService_ParseBadge(t *testing.T) {
	svc := NewBadgeService()
	ctx := context.Background()

	// Generate a badge
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	didKey := did.NewKeyDID(pub)

	claims := &badge.Claims{
		JTI:      "parse-test-jti",
		Issuer:   didKey,
		Subject:  didKey,
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(5 * time.Minute).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Level: "0",
			},
		},
	}
	token, _ := badge.SignBadge(claims, priv)

	tests := []struct {
		name       string
		req        *pb.ParseBadgeRequest
		wantClaims bool
		wantErr    bool
	}{
		{
			name:    "empty token",
			req:     &pb.ParseBadgeRequest{Token: ""},
			wantErr: true,
		},
		{
			name:    "malformed token",
			req:     &pb.ParseBadgeRequest{Token: "not-a-jws"},
			wantErr: true,
		},
		{
			name:       "valid token",
			req:        &pb.ParseBadgeRequest{Token: token},
			wantClaims: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.ParseBadge(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && resp.ErrorMessage == "" {
				t.Error("expected error message")
			}
			if tt.wantClaims && resp.Claims == nil {
				t.Error("expected claims")
			}
			if tt.wantClaims && resp.Claims != nil && resp.Claims.Jti != "parse-test-jti" {
				t.Errorf("jti = %v, want parse-test-jti", resp.Claims.Jti)
			}
		})
	}
}

func TestBadgeService_RequestBadge(t *testing.T) {
	svc := NewBadgeService()
	ctx := context.Background()

	tests := []struct {
		name      string
		req       *pb.RequestBadgeRequest
		wantCode  string
	}{
		{
			name:     "missing agent_id",
			req:      &pb.RequestBadgeRequest{AgentId: "", ApiKey: "key"},
			wantCode: "INVALID_INPUT",
		},
		{
			name:     "missing api_key",
			req:      &pb.RequestBadgeRequest{AgentId: "agent-1", ApiKey: ""},
			wantCode: "AUTH_REQUIRED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.RequestBadge(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Success {
				t.Error("expected failure")
			}
			if resp.ErrorCode != tt.wantCode {
				t.Errorf("errorCode = %v, want %v", resp.ErrorCode, tt.wantCode)
			}
		})
	}
}

func TestBadgeService_ValidateKeeperRequest(t *testing.T) {
	svc := NewBadgeService()

	tests := []struct {
		name    string
		req     *pb.StartKeeperRequest
		wantErr bool
	}{
		{
			name:    "CA mode missing agent_id",
			req:     &pb.StartKeeperRequest{Mode: pb.KeeperMode_KEEPER_MODE_CA, ApiKey: "key"},
			wantErr: true,
		},
		{
			name:    "CA mode missing api_key",
			req:     &pb.StartKeeperRequest{Mode: pb.KeeperMode_KEEPER_MODE_CA, AgentId: "agent"},
			wantErr: true,
		},
		{
			name:    "CA mode valid",
			req:     &pb.StartKeeperRequest{Mode: pb.KeeperMode_KEEPER_MODE_CA, AgentId: "agent", ApiKey: "key"},
			wantErr: false,
		},
		{
			name:    "self-sign mode missing key path",
			req:     &pb.StartKeeperRequest{Mode: pb.KeeperMode_KEEPER_MODE_SELF_SIGN},
			wantErr: true,
		},
		{
			name:    "self-sign mode valid",
			req:     &pb.StartKeeperRequest{Mode: pb.KeeperMode_KEEPER_MODE_SELF_SIGN, PrivateKeyPath: "/path/to/key"},
			wantErr: false,
		},
		{
			name:    "unknown mode",
			req:     &pb.StartKeeperRequest{Mode: pb.KeeperMode_KEEPER_MODE_UNSPECIFIED},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.validateKeeperRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeeperRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBadgeService_BuildKeeperConfig(t *testing.T) {
	svc := NewBadgeService()

	req := &pb.StartKeeperRequest{
		OutputFile:           "/tmp/badge.jwt",
		Domain:               "example.com",
		TrustLevel:           pb.TrustLevel_TRUST_LEVEL_DV,
		TtlSeconds:           300,
		RenewBeforeSeconds:   60,
		CheckIntervalSeconds: 30,
	}

	config := svc.buildKeeperConfig(req)

	if config.OutputFile != "/tmp/badge.jwt" {
		t.Errorf("OutputFile = %v, want /tmp/badge.jwt", config.OutputFile)
	}
	if config.Domain != "example.com" {
		t.Errorf("Domain = %v, want example.com", config.Domain)
	}
	if config.Expiry != 300*time.Second {
		t.Errorf("Expiry = %v, want 300s", config.Expiry)
	}
	if config.RenewBefore != 60*time.Second {
		t.Errorf("RenewBefore = %v, want 60s", config.RenewBefore)
	}
	if config.CheckInterval != 30*time.Second {
		t.Errorf("CheckInterval = %v, want 30s", config.CheckInterval)
	}
}

func TestBadgeService_ConfigureCAMode(t *testing.T) {
	svc := NewBadgeService()

	req := &pb.StartKeeperRequest{
		CaUrl:   "https://ca.example.com",
		ApiKey:  "test-key",
		AgentId: "agent-1",
	}

	config := badge.KeeperConfig{}
	svc.configureCAMode(&config, req)

	if config.Mode != badge.KeeperModeCA {
		t.Errorf("Mode = %v, want CA", config.Mode)
	}
	if config.CAURL != "https://ca.example.com" {
		t.Errorf("CAURL = %v, want https://ca.example.com", config.CAURL)
	}
	if config.APIKey != "test-key" {
		t.Errorf("APIKey = %v, want test-key", config.APIKey)
	}
	if config.AgentID != "agent-1" {
		t.Errorf("AgentID = %v, want agent-1", config.AgentID)
	}
}

func TestTrustLevelConversions(t *testing.T) {
	tests := []struct {
		level pb.TrustLevel
		str   string
	}{
		{pb.TrustLevel_TRUST_LEVEL_SELF_SIGNED, "0"},
		{pb.TrustLevel_TRUST_LEVEL_DV, "1"},
		{pb.TrustLevel_TRUST_LEVEL_OV, "2"},
		{pb.TrustLevel_TRUST_LEVEL_EV, "3"},
		{pb.TrustLevel_TRUST_LEVEL_CV, "4"},
		{pb.TrustLevel_TRUST_LEVEL_UNSPECIFIED, ""},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got := trustLevelToString(tt.level)
			if got != tt.str {
				t.Errorf("trustLevelToString(%v) = %v, want %v", tt.level, got, tt.str)
			}

			if tt.str != "" {
				back := stringToTrustLevel(tt.str)
				if back != tt.level {
					t.Errorf("stringToTrustLevel(%v) = %v, want %v", tt.str, back, tt.level)
				}
			}
		})
	}
}

func TestProtoToBadgeClaims(t *testing.T) {
	pbClaims := &pb.BadgeClaims{
		Jti:        "test-jti",
		Iss:        "did:web:example.com",
		Sub:        "did:web:example.com:agents:agent-1",
		Iat:        1000,
		Exp:        2000,
		Aud:        []string{"aud1", "aud2"},
		TrustLevel: pb.TrustLevel_TRUST_LEVEL_DV,
		Domain:     "example.com",
	}

	claims := protoToBadgeClaims(pbClaims)

	if claims.JTI != "test-jti" {
		t.Errorf("JTI = %v, want test-jti", claims.JTI)
	}
	if claims.Issuer != "did:web:example.com" {
		t.Errorf("Issuer = %v, want did:web:example.com", claims.Issuer)
	}
	if claims.Subject != "did:web:example.com:agents:agent-1" {
		t.Errorf("Subject = %v", claims.Subject)
	}
	if claims.IssuedAt != 1000 {
		t.Errorf("IssuedAt = %v, want 1000", claims.IssuedAt)
	}
	if claims.Expiry != 2000 {
		t.Errorf("Expiry = %v, want 2000", claims.Expiry)
	}
	if len(claims.Audience) != 2 {
		t.Errorf("Audience len = %v, want 2", len(claims.Audience))
	}

	// Test nil input
	if protoToBadgeClaims(nil) != nil {
		t.Error("protoToBadgeClaims(nil) should return nil")
	}
}

func TestBadgeClaimsToProto(t *testing.T) {
	claims := &badge.Claims{
		JTI:      "test-jti",
		Issuer:   "did:web:example.com",
		Subject:  "did:web:example.com:agents:agent-1",
		IssuedAt: 1000,
		Expiry:   2000,
		Audience: []string{"aud1"},
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "example.com",
				Level:  "1",
			},
		},
	}

	pbClaims := badgeClaimsToProto(claims)

	if pbClaims.Jti != "test-jti" {
		t.Errorf("Jti = %v, want test-jti", pbClaims.Jti)
	}
	if pbClaims.TrustLevel != pb.TrustLevel_TRUST_LEVEL_DV {
		t.Errorf("TrustLevel = %v, want DV", pbClaims.TrustLevel)
	}
	if pbClaims.Domain != "example.com" {
		t.Errorf("Domain = %v, want example.com", pbClaims.Domain)
	}

	// Test nil input
	if badgeClaimsToProto(nil) != nil {
		t.Error("badgeClaimsToProto(nil) should return nil")
	}
}

func TestKeeperEventTypeToPB(t *testing.T) {
	tests := []struct {
		event  badge.KeeperEventType
		expect pb.KeeperEventType
	}{
		{badge.KeeperEventStarted, pb.KeeperEventType_KEEPER_EVENT_STARTED},
		{badge.KeeperEventRenewed, pb.KeeperEventType_KEEPER_EVENT_RENEWED},
		{badge.KeeperEventError, pb.KeeperEventType_KEEPER_EVENT_ERROR},
		{badge.KeeperEventStopped, pb.KeeperEventType_KEEPER_EVENT_STOPPED},
	}

	for _, tt := range tests {
		got := keeperEventTypeToPB(tt.event)
		if got != tt.expect {
			t.Errorf("keeperEventTypeToPB(%v) = %v, want %v", tt.event, got, tt.expect)
		}
	}
}

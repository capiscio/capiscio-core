package rpc

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
)

func TestNewSimpleGuardService(t *testing.T) {
	svc := NewSimpleGuardService()
	if svc == nil {
		t.Fatal("NewSimpleGuardService returned nil")
	}
	if svc.keys == nil {
		t.Error("keys map should be initialized")
	}
}

func TestSimpleGuardService_GenerateKeyPair(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	tests := []struct {
		name      string
		req       *pb.GenerateKeyPairRequest
		wantErr   bool
		wantKeyID string
	}{
		{
			name:    "default algorithm",
			req:     &pb.GenerateKeyPairRequest{},
			wantErr: false,
		},
		{
			name:    "explicit Ed25519",
			req:     &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm_KEY_ALGORITHM_ED25519},
			wantErr: false,
		},
		{
			name:      "custom key ID",
			req:       &pb.GenerateKeyPairRequest{KeyId: "my-custom-key"},
			wantKeyID: "my-custom-key",
		},
		{
			name:    "unsupported algorithm",
			req:     &pb.GenerateKeyPairRequest{Algorithm: pb.KeyAlgorithm(999)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.GenerateKeyPair(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if resp.KeyId == "" {
				t.Error("expected key ID")
			}
			if tt.wantKeyID != "" && resp.KeyId != tt.wantKeyID {
				t.Errorf("keyId = %v, want %v", resp.KeyId, tt.wantKeyID)
			}
			if len(resp.PublicKey) != 32 {
				t.Errorf("public key length = %v, want 32", len(resp.PublicKey))
			}
			if len(resp.PrivateKey) != 32 {
				t.Errorf("private key seed length = %v, want 32", len(resp.PrivateKey))
			}
			if resp.PublicKeyPem == "" {
				t.Error("expected public key PEM")
			}
			if resp.PrivateKeyPem == "" {
				t.Error("expected private key PEM")
			}
			if resp.DidKey == "" {
				t.Error("expected did:key")
			}
		})
	}
}

func TestSimpleGuardService_Sign(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate a key first
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "sign-test-key"})

	tests := []struct {
		name    string
		req     *pb.SignRequest
		wantErr bool
	}{
		{
			name:    "unknown key",
			req:     &pb.SignRequest{KeyId: "unknown-key", Payload: []byte("test")},
			wantErr: true,
		},
		{
			name:    "valid sign",
			req:     &pb.SignRequest{KeyId: genResp.KeyId, Payload: []byte("test message")},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.Sign(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if len(resp.Signature) == 0 {
				t.Error("expected signature")
			}
			if resp.SignatureString == "" {
				t.Error("expected signature string")
			}
		})
	}
}

func TestSimpleGuardService_Verify(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate a key and sign a message
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "verify-test-key"})
	payload := []byte("test message")
	signResp, _ := svc.Sign(ctx, &pb.SignRequest{KeyId: genResp.KeyId, Payload: payload})

	tests := []struct {
		name      string
		req       *pb.VerifyRequest
		wantValid bool
	}{
		{
			name: "valid signature",
			req: &pb.VerifyRequest{
				Payload:   payload,
				Signature: signResp.Signature,
			},
			wantValid: true,
		},
		{
			name: "valid signature string",
			req: &pb.VerifyRequest{
				Payload:         payload,
				SignatureString: signResp.SignatureString,
			},
			wantValid: true,
		},
		{
			name: "wrong payload",
			req: &pb.VerifyRequest{
				Payload:   []byte("wrong message"),
				Signature: signResp.Signature,
			},
			wantValid: false,
		},
		{
			name: "invalid signature encoding",
			req: &pb.VerifyRequest{
				Payload:         payload,
				SignatureString: "not-base64!@#$",
			},
			wantValid: false,
		},
		{
			name: "with expected signer",
			req: &pb.VerifyRequest{
				Payload:        payload,
				Signature:      signResp.Signature,
				ExpectedSigner: genResp.KeyId,
			},
			wantValid: true,
		},
		{
			name: "wrong expected signer",
			req: &pb.VerifyRequest{
				Payload:        payload,
				Signature:      signResp.Signature,
				ExpectedSigner: "wrong-key",
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.Verify(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Valid != tt.wantValid {
				t.Errorf("valid = %v, want %v (error: %s)", resp.Valid, tt.wantValid, resp.ErrorMessage)
			}
		})
	}
}

func TestSimpleGuardService_SignAttached(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate a key
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "attached-test-key"})

	tests := []struct {
		name    string
		req     *pb.SignAttachedRequest
		wantErr bool
	}{
		{
			name:    "unknown key",
			req:     &pb.SignAttachedRequest{KeyId: "unknown-key"},
			wantErr: true,
		},
		{
			name:    "valid without payload",
			req:     &pb.SignAttachedRequest{KeyId: genResp.KeyId},
			wantErr: false,
		},
		{
			name:    "valid with payload",
			req:     &pb.SignAttachedRequest{KeyId: genResp.KeyId, Payload: []byte("test body")},
			wantErr: false,
		},
		{
			name: "valid with headers",
			req: &pb.SignAttachedRequest{
				KeyId:   genResp.KeyId,
				Payload: []byte("test"),
				Headers: map[string]string{"x-custom": "value"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.SignAttached(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if resp.Jws == "" {
				t.Error("expected JWS")
			}
		})
	}
}

func TestSimpleGuardService_VerifyAttached(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate a key and create JWS
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "verify-attached-key"})
	body := []byte("test body content")
	signResp, _ := svc.SignAttached(ctx, &pb.SignAttachedRequest{KeyId: genResp.KeyId, Payload: body})

	tests := []struct {
		name      string
		req       *pb.VerifyAttachedRequest
		wantValid bool
	}{
		{
			name:      "invalid JWS format",
			req:       &pb.VerifyAttachedRequest{Jws: "not-a-jws"},
			wantValid: false,
		},
		{
			name:      "valid JWS with body",
			req:       &pb.VerifyAttachedRequest{Jws: signResp.Jws, DetachedPayload: body},
			wantValid: true,
		},
		{
			name:      "wrong body hash",
			req:       &pb.VerifyAttachedRequest{Jws: signResp.Jws, DetachedPayload: []byte("wrong body")},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.VerifyAttached(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Valid != tt.wantValid {
				t.Errorf("valid = %v, want %v (error: %s)", resp.Valid, tt.wantValid, resp.ErrorMessage)
			}
		})
	}
}

func TestSimpleGuardService_GetKeyInfo(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate a key
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{
		KeyId:    "info-test-key",
		Metadata: map[string]string{"purpose": "testing"},
	})

	tests := []struct {
		name    string
		keyID   string
		wantErr bool
	}{
		{
			name:    "unknown key",
			keyID:   "unknown-key",
			wantErr: true,
		},
		{
			name:    "existing key",
			keyID:   genResp.KeyId,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.GetKeyInfo(ctx, &pb.GetKeyInfoRequest{KeyId: tt.keyID})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if resp.KeyId != tt.keyID {
				t.Errorf("keyId = %v, want %v", resp.KeyId, tt.keyID)
			}
			if !resp.HasPrivateKey {
				t.Error("expected has_private_key = true")
			}
			if len(resp.PublicKey) != 32 {
				t.Errorf("public key length = %v, want 32", len(resp.PublicKey))
			}
		})
	}
}

func TestSimpleGuardService_ExportKey(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate a key
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "export-test-key"})

	// Create temp dir for exports
	tmpDir := t.TempDir()

	tests := []struct {
		name           string
		keyID          string
		includePrivate bool
		wantErr        bool
	}{
		{
			name:    "unknown key",
			keyID:   "unknown-key",
			wantErr: true,
		},
		{
			name:           "export public only",
			keyID:          genResp.KeyId,
			includePrivate: false,
			wantErr:        false,
		},
		{
			name:           "export with private",
			keyID:          genResp.KeyId,
			includePrivate: true,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tmpDir, tt.name+".pem")
			resp, err := svc.ExportKey(ctx, &pb.ExportKeyRequest{
				KeyId:          tt.keyID,
				FilePath:       filePath,
				IncludePrivate: tt.includePrivate,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if resp.FilePath != filePath {
				t.Errorf("filePath = %v, want %v", resp.FilePath, filePath)
			}
			// Verify file exists
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Error("exported file does not exist")
			}
		})
	}
}

func TestSimpleGuardService_LoadKey(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate and export a key first
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "load-source-key"})
	tmpDir := t.TempDir()
	privPath := filepath.Join(tmpDir, "private.pem")
	pubPath := filepath.Join(tmpDir, "public.pem")

	svc.ExportKey(ctx, &pb.ExportKeyRequest{KeyId: genResp.KeyId, FilePath: privPath, IncludePrivate: true})
	svc.ExportKey(ctx, &pb.ExportKeyRequest{KeyId: genResp.KeyId, FilePath: pubPath, IncludePrivate: false})

	// Create invalid PEM file
	invalidPath := filepath.Join(tmpDir, "invalid.pem")
	os.WriteFile(invalidPath, []byte("not a PEM file"), 0600)

	tests := []struct {
		name           string
		filePath       string
		wantErr        bool
		wantPrivateKey bool
	}{
		{
			name:     "file not found",
			filePath: "/nonexistent/file.pem",
			wantErr:  true,
		},
		{
			name:     "invalid PEM",
			filePath: invalidPath,
			wantErr:  true,
		},
		{
			name:           "load private key",
			filePath:       privPath,
			wantPrivateKey: true,
		},
		{
			name:           "load public key only",
			filePath:       pubPath,
			wantPrivateKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := svc.LoadKey(ctx, &pb.LoadKeyRequest{FilePath: tt.filePath})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				if resp.ErrorMessage == "" {
					t.Error("expected error message")
				}
				return
			}
			if resp.ErrorMessage != "" {
				t.Errorf("unexpected error: %s", resp.ErrorMessage)
			}
			if resp.KeyId == "" {
				t.Error("expected key ID")
			}
			if resp.HasPrivateKey != tt.wantPrivateKey {
				t.Errorf("hasPrivateKey = %v, want %v", resp.HasPrivateKey, tt.wantPrivateKey)
			}
		})
	}
}

func TestSimpleGuardService_SignWithPublicKeyOnly(t *testing.T) {
	svc := NewSimpleGuardService()
	ctx := context.Background()

	// Generate key, export public only, create new service and load public only
	genResp, _ := svc.GenerateKeyPair(ctx, &pb.GenerateKeyPairRequest{KeyId: "pub-only-key"})
	tmpDir := t.TempDir()
	pubPath := filepath.Join(tmpDir, "public.pem")
	svc.ExportKey(ctx, &pb.ExportKeyRequest{KeyId: genResp.KeyId, FilePath: pubPath, IncludePrivate: false})

	// New service, load only public key
	svc2 := NewSimpleGuardService()
	loadResp, _ := svc2.LoadKey(ctx, &pb.LoadKeyRequest{FilePath: pubPath})

	// Try to sign - should fail because no private key
	signResp, err := svc2.Sign(ctx, &pb.SignRequest{KeyId: loadResp.KeyId, Payload: []byte("test")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signResp.ErrorMessage == "" {
		t.Error("expected error when signing with public key only")
	}
}

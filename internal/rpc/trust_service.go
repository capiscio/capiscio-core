package rpc

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"

	pb "github.com/capiscio/capiscio-core/pkg/rpc/gen/capiscio/v1"
	"github.com/capiscio/capiscio-core/pkg/trust"
)

// TrustStoreService implements the gRPC TrustStoreService.
type TrustStoreService struct {
	pb.UnimplementedTrustStoreServiceServer
	store *trust.FileStore
}

// NewTrustStoreService creates a new TrustStoreService instance.
func NewTrustStoreService() (*TrustStoreService, error) {
	store, err := trust.NewFileStore("")
	if err != nil {
		return nil, fmt.Errorf("failed to create trust store: %w", err)
	}
	return &TrustStoreService{store: store}, nil
}

// AddKey adds a trusted public key.
func (s *TrustStoreService) AddKey(ctx context.Context, req *pb.AddKeyRequest) (*pb.AddKeyResponse, error) {
	var jwk jose.JSONWebKey

	switch req.Format {
	case pb.KeyFormat_KEY_FORMAT_JWK:
		if err := json.Unmarshal(req.PublicKey, &jwk); err != nil {
			return &pb.AddKeyResponse{
				ErrorMessage: fmt.Sprintf("invalid JWK: %v", err),
			}, nil
		}
	case pb.KeyFormat_KEY_FORMAT_PEM:
		// Parse PEM
		block, _ := pem.Decode(req.PublicKey)
		if block == nil {
			return &pb.AddKeyResponse{
				ErrorMessage: "invalid PEM format",
			}, nil
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return &pb.AddKeyResponse{
				ErrorMessage: fmt.Sprintf("invalid public key: %v", err),
			}, nil
		}
		// Create JWK from public key
		jwk = jose.JSONWebKey{
			Key:       pub,
			KeyID:     req.Did, // Use DID as key ID if not specified
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}
	default:
		return &pb.AddKeyResponse{
			ErrorMessage: "unsupported key format",
		}, nil
	}

	// Use DID as key ID if not already set
	if jwk.KeyID == "" {
		jwk.KeyID = req.Did
	}

	if err := s.store.Add(jwk); err != nil {
		return &pb.AddKeyResponse{
			ErrorMessage: fmt.Sprintf("failed to add key: %v", err),
		}, nil
	}

	return &pb.AddKeyResponse{
		KeyId: jwk.KeyID,
	}, nil
}

// RemoveKey removes a trusted key.
func (s *TrustStoreService) RemoveKey(ctx context.Context, req *pb.RemoveKeyRequest) (*pb.RemoveKeyResponse, error) {
	if err := s.store.Remove(req.Did); err != nil {
		return &pb.RemoveKeyResponse{
			ErrorMessage: fmt.Sprintf("failed to remove key: %v", err),
		}, nil
	}
	return &pb.RemoveKeyResponse{}, nil
}

// GetKey gets a key by DID.
func (s *TrustStoreService) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	jwk, err := s.store.Get(req.Did)
	if err != nil {
		return &pb.GetKeyResponse{
			ErrorMessage: fmt.Sprintf("key not found: %v", err),
		}, nil
	}

	// Convert to protobuf TrustedKey
	keyBytes, _ := json.Marshal(jwk)

	return &pb.GetKeyResponse{
		Key: &pb.TrustedKey{
			Did:       jwk.KeyID,
			PublicKey: keyBytes,
			Format:    pb.KeyFormat_KEY_FORMAT_JWK,
			Algorithm: algorithmToProto(jwk.Algorithm),
		},
	}, nil
}

// ListKeys lists all trusted keys.
func (s *TrustStoreService) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	keys, err := s.store.List()
	if err != nil {
		return &pb.ListKeysResponse{}, nil
	}

	var pbKeys []*pb.TrustedKey
	for _, jwk := range keys {
		keyBytes, _ := json.Marshal(jwk)
		pbKeys = append(pbKeys, &pb.TrustedKey{
			Did:       jwk.KeyID,
			PublicKey: keyBytes,
			Format:    pb.KeyFormat_KEY_FORMAT_JWK,
			Algorithm: algorithmToProto(jwk.Algorithm),
		})
	}

	return &pb.ListKeysResponse{
		Keys: pbKeys,
	}, nil
}

// IsTrusted checks if a key is trusted.
func (s *TrustStoreService) IsTrusted(ctx context.Context, req *pb.IsTrustedRequest) (*pb.IsTrustedResponse, error) {
	_, err := s.store.Get(req.Did)
	return &pb.IsTrustedResponse{
		IsTrusted: err == nil,
	}, nil
}

// ImportFromDirectory imports keys from a directory.
func (s *TrustStoreService) ImportFromDirectory(ctx context.Context, req *pb.ImportFromDirectoryRequest) (*pb.ImportFromDirectoryResponse, error) {
	entries, err := os.ReadDir(req.DirectoryPath)
	if err != nil {
		return &pb.ImportFromDirectoryResponse{
			Errors: []string{fmt.Sprintf("failed to read directory: %v", err)},
		}, nil
	}

	var imported int32
	var errors []string

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := filepath.Ext(entry.Name())
		if ext != ".jwk" && ext != ".pem" {
			continue
		}

		path := filepath.Join(req.DirectoryPath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to read %s: %v", entry.Name(), err))
			continue
		}

		var jwk jose.JSONWebKey

		if ext == ".jwk" {
			if err := json.Unmarshal(data, &jwk); err != nil {
				errors = append(errors, fmt.Sprintf("invalid JWK in %s: %v", entry.Name(), err))
				continue
			}
		} else if ext == ".pem" {
			block, _ := pem.Decode(data)
			if block == nil {
				errors = append(errors, fmt.Sprintf("invalid PEM in %s", entry.Name()))
				continue
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				errors = append(errors, fmt.Sprintf("invalid public key in %s: %v", entry.Name(), err))
				continue
			}
			// Use filename (without extension) as key ID
			kid := entry.Name()[:len(entry.Name())-len(ext)]
			jwk = jose.JSONWebKey{
				Key:   pub,
				KeyID: kid,
				Use:   "sig",
			}
			if _, ok := pub.(ed25519.PublicKey); ok {
				jwk.Algorithm = string(jose.EdDSA)
			}
		}

		if jwk.KeyID == "" {
			errors = append(errors, fmt.Sprintf("missing key ID in %s", entry.Name()))
			continue
		}

		if err := s.store.Add(jwk); err != nil {
			errors = append(errors, fmt.Sprintf("failed to add key from %s: %v", entry.Name(), err))
			continue
		}

		imported++
	}

	return &pb.ImportFromDirectoryResponse{
		KeysImported: imported,
		Errors:       errors,
	}, nil
}

// ExportToDirectory exports keys to a directory.
func (s *TrustStoreService) ExportToDirectory(ctx context.Context, req *pb.ExportToDirectoryRequest) (*pb.ExportToDirectoryResponse, error) {
	keys, err := s.store.List()
	if err != nil {
		return &pb.ExportToDirectoryResponse{
			ErrorMessage: fmt.Sprintf("failed to list keys: %v", err),
		}, nil
	}

	// Ensure directory exists
	if err := os.MkdirAll(req.DirectoryPath, 0700); err != nil {
		return &pb.ExportToDirectoryResponse{
			ErrorMessage: fmt.Sprintf("failed to create directory: %v", err),
		}, nil
	}

	var exported int32
	for _, jwk := range keys {
		var data []byte
		var ext string

		switch req.Format {
		case pb.KeyFormat_KEY_FORMAT_JWK:
			data, _ = json.MarshalIndent(jwk, "", "  ")
			ext = ".jwk"
		case pb.KeyFormat_KEY_FORMAT_PEM:
			pub, ok := jwk.Key.(ed25519.PublicKey)
			if !ok {
				continue
			}
			pubPKIX, _ := x509.MarshalPKIXPublicKey(pub)
			data = pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: pubPKIX,
			})
			ext = ".pem"
		default:
			data, _ = json.MarshalIndent(jwk, "", "  ")
			ext = ".jwk"
		}

		path := filepath.Join(req.DirectoryPath, sanitizeFilename(jwk.KeyID)+ext)
		if err := os.WriteFile(path, data, 0600); err != nil {
			continue
		}
		exported++
	}

	return &pb.ExportToDirectoryResponse{
		KeysExported: exported,
	}, nil
}

// Clear clears all keys.
func (s *TrustStoreService) Clear(ctx context.Context, req *pb.ClearKeysRequest) (*pb.ClearKeysResponse, error) {
	keys, err := s.store.List()
	if err != nil {
		return &pb.ClearKeysResponse{}, nil
	}

	var removed int32
	for _, jwk := range keys {
		if err := s.store.Remove(jwk.KeyID); err == nil {
			removed++
		}
	}

	return &pb.ClearKeysResponse{
		KeysCleared: removed,
	}, nil
}

// Ping responds to health checks.
func (s *TrustStoreService) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{
		Status:  "ok",
		Version: "1.0.0",
		ServerTime: &pb.Timestamp{
			Value: time.Now().Format(time.RFC3339),
		},
	}, nil
}

// algorithmToProto converts a JWK algorithm string to protobuf KeyAlgorithm.
func algorithmToProto(alg string) pb.KeyAlgorithm {
	switch alg {
	case "EdDSA":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ED25519
	case "ES256":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case "ES384":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384
	case "RS256", "RS384", "RS512":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	default:
		return pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

// sanitizeFilename converts a string to a safe filename.
func sanitizeFilename(s string) string {
	safe := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch c {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			safe = append(safe, '_')
		default:
			safe = append(safe, c)
		}
	}
	return string(safe)
}

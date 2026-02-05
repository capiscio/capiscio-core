package rpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/capiscio/capiscio-core/v2/pkg/did"
	pb "github.com/capiscio/capiscio-core/v2/pkg/rpc/gen/capiscio/v1"
)

// KeyEntry holds a loaded key pair.
type KeyEntry struct {
	KeyID      string
	Algorithm  pb.KeyAlgorithm
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey // may be nil if only public key loaded
	CreatedAt  time.Time
	Metadata   map[string]string
}

// SimpleGuardService implements the gRPC SimpleGuardService.
type SimpleGuardService struct {
	pb.UnimplementedSimpleGuardServiceServer
	mu   sync.RWMutex
	keys map[string]*KeyEntry // keyID -> KeyEntry
}

// NewSimpleGuardService creates a new SimpleGuardService instance.
func NewSimpleGuardService() *SimpleGuardService {
	return &SimpleGuardService{
		keys: make(map[string]*KeyEntry),
	}
}

// Sign signs a message using the specified key.
func (s *SimpleGuardService) Sign(_ context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	s.mu.RLock()
	entry, exists := s.keys[req.KeyId]
	s.mu.RUnlock()

	if !exists {
		return &pb.SignResponse{
			ErrorMessage: fmt.Sprintf("key not found: %s", req.KeyId),
		}, nil
	}

	if entry.PrivateKey == nil {
		return &pb.SignResponse{
			ErrorMessage: fmt.Sprintf("no private key available for: %s", req.KeyId),
		}, nil
	}

	// Sign the payload
	signature := ed25519.Sign(entry.PrivateKey, req.Payload)

	return &pb.SignResponse{
		Signature:       signature,
		SignatureString: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

// Verify verifies a signed message.
func (s *SimpleGuardService) Verify(_ context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	// If we have a signature string, decode it
	sig := req.Signature
	if len(sig) == 0 && req.SignatureString != "" {
		var err error
		sig, err = base64.RawURLEncoding.DecodeString(req.SignatureString)
		if err != nil {
			return &pb.VerifyResponse{
				Valid:        false,
				ErrorMessage: fmt.Sprintf("invalid signature encoding: %v", err),
			}, nil
		}
	}

	// Try all loaded public keys if no specific signer expected
	s.mu.RLock()
	defer s.mu.RUnlock()

	for keyID, entry := range s.keys {
		if req.ExpectedSigner != "" && keyID != req.ExpectedSigner {
			continue
		}

		if ed25519.Verify(entry.PublicKey, req.Payload, sig) {
			return &pb.VerifyResponse{
				Valid:    true,
				KeyId:    keyID,
				SignerDid: "", // Would need DID mapping
			}, nil
		}
	}

	return &pb.VerifyResponse{
		Valid:        false,
		ErrorMessage: "signature verification failed: no matching key found",
	}, nil
}

// SignAttached signs with attached payload (creates JWS).
func (s *SimpleGuardService) SignAttached(_ context.Context, req *pb.SignAttachedRequest) (*pb.SignAttachedResponse, error) {
	s.mu.RLock()
	entry, exists := s.keys[req.KeyId]
	s.mu.RUnlock()

	if !exists {
		return &pb.SignAttachedResponse{
			ErrorMessage: fmt.Sprintf("key not found: %s", req.KeyId),
		}, nil
	}

	if entry.PrivateKey == nil {
		return &pb.SignAttachedResponse{
			ErrorMessage: fmt.Sprintf("no private key available for: %s", req.KeyId),
		}, nil
	}

	// Create signer
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader("kid", req.KeyId)

	// Add custom headers
	for k, v := range req.Headers {
		opts.WithHeader(jose.HeaderKey(k), v)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: entry.PrivateKey}, opts)
	if err != nil {
		return &pb.SignAttachedResponse{
			ErrorMessage: fmt.Sprintf("failed to create signer: %v", err),
		}, nil
	}

	// Build claims with timestamps
	now := time.Now()
	claims := map[string]interface{}{
		"iat": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
	}

	// Add body hash if payload provided
	if len(req.Payload) > 0 {
		hash := sha256.Sum256(req.Payload)
		claims["bh"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	// Marshal claims
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return &pb.SignAttachedResponse{
			ErrorMessage: fmt.Sprintf("failed to marshal claims: %v", err),
		}, nil
	}

	// Sign
	jwsObj, err := signer.Sign(payloadBytes)
	if err != nil {
		return &pb.SignAttachedResponse{
			ErrorMessage: fmt.Sprintf("failed to sign: %v", err),
		}, nil
	}

	compact, err := jwsObj.CompactSerialize()
	if err != nil {
		return &pb.SignAttachedResponse{
			ErrorMessage: fmt.Sprintf("failed to serialize: %v", err),
		}, nil
	}

	return &pb.SignAttachedResponse{
		Jws: compact,
	}, nil
}

// VerifyAttached verifies with attached payload.
func (s *SimpleGuardService) VerifyAttached(_ context.Context, req *pb.VerifyAttachedRequest) (*pb.VerifyAttachedResponse, error) {
	// Parse JWS
	jwsObj, err := jose.ParseSigned(req.Jws, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return &pb.VerifyAttachedResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("invalid JWS format: %v", err),
		}, nil
	}

	// Get kid from header - use the KeyID field from protected header
	var kid string
	if len(jwsObj.Signatures) > 0 {
		kid = jwsObj.Signatures[0].Header.KeyID
	}

	// Find key
	s.mu.RLock()
	entry, exists := s.keys[kid]
	s.mu.RUnlock()

	if !exists {
		return &pb.VerifyAttachedResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("untrusted key: %s", kid),
		}, nil
	}

	// Verify signature
	payload, err := jwsObj.Verify(entry.PublicKey)
	if err != nil {
		return &pb.VerifyAttachedResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("signature verification failed: %v", err),
		}, nil
	}

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return &pb.VerifyAttachedResponse{
			Valid:        false,
			ErrorMessage: fmt.Sprintf("invalid claims: %v", err),
		}, nil
	}

	// Check timestamps
	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) <= now {
			return &pb.VerifyAttachedResponse{
				Valid:        false,
				ErrorMessage: "token expired",
			}, nil
		}
	}

	// Verify body hash if present
	if bh, ok := claims["bh"].(string); ok {
		body := req.DetachedPayload
		if len(body) == 0 {
			return &pb.VerifyAttachedResponse{
				Valid:        false,
				ErrorMessage: "body hash present but no body provided",
			}, nil
		}

		hash := sha256.Sum256(body)
		expectedBH := base64.RawURLEncoding.EncodeToString(hash[:])
		if bh != expectedBH {
			return &pb.VerifyAttachedResponse{
				Valid:        false,
				ErrorMessage: "body hash mismatch",
			}, nil
		}
	}

	return &pb.VerifyAttachedResponse{
		Valid:   true,
		Payload: payload,
		KeyId:   kid,
	}, nil
}

// GenerateKeyPair generates a new key pair.
func (s *SimpleGuardService) GenerateKeyPair(_ context.Context, req *pb.GenerateKeyPairRequest) (*pb.GenerateKeyPairResponse, error) {
	// Only Ed25519 supported for now
	if req.Algorithm != pb.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED && req.Algorithm != pb.KeyAlgorithm_KEY_ALGORITHM_ED25519 {
		return &pb.GenerateKeyPairResponse{
			ErrorMessage: "only Ed25519 algorithm is supported",
		}, nil
	}

	// Generate key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return &pb.GenerateKeyPairResponse{
			ErrorMessage: fmt.Sprintf("failed to generate key: %v", err),
		}, nil
	}

	// Generate key ID
	keyID := req.KeyId
	if keyID == "" {
		// Use first 8 chars of public key hash
		hash := sha256.Sum256(pub)
		keyID = fmt.Sprintf("key-%s", base64.RawURLEncoding.EncodeToString(hash[:4]))
	}

	// Store key
	entry := &KeyEntry{
		KeyID:      keyID,
		Algorithm:  pb.KeyAlgorithm_KEY_ALGORITHM_ED25519,
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
		Metadata:   req.Metadata,
	}

	s.mu.Lock()
	s.keys[keyID] = entry
	s.mu.Unlock()

	// Encode keys
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(priv),
	})

	pubPKIX, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubPKIX,
	})

	// Generate did:key URI from public key (RFC-002 §6.1)
	didKey := did.NewKeyDID(pub)

	return &pb.GenerateKeyPairResponse{
		KeyId:         keyID,
		PublicKey:     pub,
		PrivateKey:    priv.Seed(), // Return seed (32 bytes) not full private key
		PublicKeyPem:  string(pubPEM),
		PrivateKeyPem: string(privPEM),
		Algorithm:     pb.KeyAlgorithm_KEY_ALGORITHM_ED25519,
		DidKey:        didKey,
	}, nil
}

// LoadKey loads key from file.
func (s *SimpleGuardService) LoadKey(_ context.Context, req *pb.LoadKeyRequest) (*pb.LoadKeyResponse, error) {
	// Read file
	data, err := os.ReadFile(req.FilePath)
	if err != nil {
		return &pb.LoadKeyResponse{
			ErrorMessage: fmt.Sprintf("failed to read file: %v", err),
		}, nil
	}

	// Parse PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return &pb.LoadKeyResponse{
			ErrorMessage: "failed to decode PEM",
		}, nil
	}

	var entry KeyEntry
	entry.CreatedAt = time.Now()

	// Try parsing as private key first
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return &pb.LoadKeyResponse{
				ErrorMessage: fmt.Sprintf("failed to parse private key: %v", err),
			}, nil
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return &pb.LoadKeyResponse{
				ErrorMessage: "key is not Ed25519",
			}, nil
		}
		entry.PrivateKey = edKey
		entry.PublicKey = edKey.Public().(ed25519.PublicKey)
		entry.Algorithm = pb.KeyAlgorithm_KEY_ALGORITHM_ED25519

	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return &pb.LoadKeyResponse{
				ErrorMessage: fmt.Sprintf("failed to parse public key: %v", err),
			}, nil
		}
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return &pb.LoadKeyResponse{
				ErrorMessage: "key is not Ed25519",
			}, nil
		}
		entry.PublicKey = edKey
		entry.Algorithm = pb.KeyAlgorithm_KEY_ALGORITHM_ED25519

	default:
		return &pb.LoadKeyResponse{
			ErrorMessage: fmt.Sprintf("unsupported PEM type: %s", block.Type),
		}, nil
	}

	// Generate key ID from filename
	entry.KeyID = filepath.Base(req.FilePath)
	entry.KeyID = entry.KeyID[:len(entry.KeyID)-len(filepath.Ext(entry.KeyID))]

	s.mu.Lock()
	s.keys[entry.KeyID] = &entry
	s.mu.Unlock()

	return &pb.LoadKeyResponse{
		KeyId:         entry.KeyID,
		Algorithm:     entry.Algorithm,
		HasPrivateKey: entry.PrivateKey != nil,
	}, nil
}

// ExportKey exports key to file.
func (s *SimpleGuardService) ExportKey(_ context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	s.mu.RLock()
	entry, exists := s.keys[req.KeyId]
	s.mu.RUnlock()

	if !exists {
		return &pb.ExportKeyResponse{
			ErrorMessage: fmt.Sprintf("key not found: %s", req.KeyId),
		}, nil
	}

	var pemData []byte

	if req.IncludePrivate {
		if entry.PrivateKey == nil {
			return &pb.ExportKeyResponse{
				ErrorMessage: "no private key available",
			}, nil
		}
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: mustMarshalPKCS8(entry.PrivateKey),
		})
	} else {
		pubPKIX, _ := x509.MarshalPKIXPublicKey(entry.PublicKey)
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubPKIX,
		})
	}

	if err := os.WriteFile(req.FilePath, pemData, 0600); err != nil {
		return &pb.ExportKeyResponse{
			ErrorMessage: fmt.Sprintf("failed to write file: %v", err),
		}, nil
	}

	return &pb.ExportKeyResponse{
		FilePath: req.FilePath,
	}, nil
}

// GetKeyInfo gets key info.
func (s *SimpleGuardService) GetKeyInfo(_ context.Context, req *pb.GetKeyInfoRequest) (*pb.GetKeyInfoResponse, error) {
	s.mu.RLock()
	entry, exists := s.keys[req.KeyId]
	s.mu.RUnlock()

	if !exists {
		return &pb.GetKeyInfoResponse{
			ErrorMessage: fmt.Sprintf("key not found: %s", req.KeyId),
		}, nil
	}

	pubPKIX, _ := x509.MarshalPKIXPublicKey(entry.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubPKIX,
	})

	return &pb.GetKeyInfoResponse{
		KeyId:         entry.KeyID,
		Algorithm:     entry.Algorithm,
		HasPrivateKey: entry.PrivateKey != nil,
		PublicKey:     entry.PublicKey,
		PublicKeyPem:  string(pubPEM),
		CreatedAt:     &pb.Timestamp{Value: entry.CreatedAt.Format(time.RFC3339)},
		Metadata:      entry.Metadata,
	}, nil
}

func mustMarshalPKCS8(key ed25519.PrivateKey) []byte {
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return data
}

// Init initializes agent identity - one-call setup (Let's Encrypt style).
// Generates key pair, derives DID, registers with server, creates agent card.
func (s *SimpleGuardService) Init(_ context.Context, req *pb.InitRequest) (*pb.InitResponse, error) {
	// Defaults
	serverURL := req.ServerUrl
	if serverURL == "" {
		serverURL = "https://api.capisc.io"
	}
	outputDir := req.OutputDir
	if outputDir == "" {
		outputDir = ".capiscio"
	}

	// Check if files exist and force flag
	privKeyPath := filepath.Join(outputDir, "private.jwk")
	if _, err := os.Stat(privKeyPath); err == nil && !req.Force {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("identity already exists at %s (use force=true to overwrite)", outputDir),
		}, nil
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to create output directory: %v", err),
		}, nil
	}

	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to generate key pair: %v", err),
		}, nil
	}

	// Derive DID
	didKey := did.NewKeyDID(pub)

	// Create JWK for storage
	jwk := jose.JSONWebKey{
		Key:       priv,
		KeyID:     didKey,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	jwkBytes, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to marshal JWK: %v", err),
		}, nil
	}

	pubJWK := jwk.Public()
	pubJWKBytes, err := json.MarshalIndent(pubJWK, "", "  ")
	if err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to marshal public JWK: %v", err),
		}, nil
	}

	// Write private key (restrictive permissions)
	if err := os.WriteFile(privKeyPath, jwkBytes, 0600); err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to write private key: %v", err),
		}, nil
	}

	// Write public key
	pubKeyPath := filepath.Join(outputDir, "public.jwk")
	if err := os.WriteFile(pubKeyPath, pubJWKBytes, 0644); err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to write public key: %v", err),
		}, nil
	}

	// Register DID with server if API key and agent ID provided
	registered := false
	if req.ApiKey != "" && req.AgentId != "" {
		if err := s.registerDIDWithServer(serverURL, req.ApiKey, req.AgentId, didKey, pubJWKBytes); err != nil {
			return &pb.InitResponse{
				Did:            didKey,
				PrivateKeyPath: privKeyPath,
				PublicKeyPath:  pubKeyPath,
				ErrorMessage:   fmt.Sprintf("key generated but registration failed: %v", err),
			}, nil
		}
		registered = true
	}

	// Create agent card
	agentCard := map[string]interface{}{
		"@context":        "https://capisc.io/ns/agent-card/v1",
		"id":              didKey,
		"name":            fmt.Sprintf("Agent %s", req.AgentId),
		"description":     "CapiscIO verified agent",
		"created":         time.Now().UTC().Format(time.RFC3339),
		"verificationMethods": []map[string]interface{}{
			{
				"id":           fmt.Sprintf("%s#keys-1", didKey),
				"type":         "JsonWebKey2020",
				"controller":   didKey,
				"publicKeyJwk": pubJWK,
			},
		},
	}

	if req.AgentId != "" {
		agentCard["capiscio:agentId"] = req.AgentId
	}

	// Add any custom metadata
	for k, v := range req.Metadata {
		agentCard[k] = v
	}

	agentCardBytes, err := json.MarshalIndent(agentCard, "", "  ")
	if err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to marshal agent card: %v", err),
		}, nil
	}

	agentCardPath := filepath.Join(outputDir, "agent-card.json")
	if err := os.WriteFile(agentCardPath, agentCardBytes, 0644); err != nil {
		return &pb.InitResponse{
			ErrorMessage: fmt.Sprintf("failed to write agent card: %v", err),
		}, nil
	}

	return &pb.InitResponse{
		Did:            didKey,
		AgentId:        req.AgentId,
		PrivateKeyPath: privKeyPath,
		PublicKeyPath:  pubKeyPath,
		AgentCardPath:  agentCardPath,
		AgentCardJson:  string(agentCardBytes),
		Registered:     registered,
	}, nil
}

// registerDIDWithServer registers DID with the CapiscIO server.
func (s *SimpleGuardService) registerDIDWithServer(serverURL, apiKey, agentID, didKey string, publicKeyJWK []byte) error {
	url := fmt.Sprintf("%s/v1/agents/%s/dids", serverURL, agentID)

	payload := map[string]interface{}{
		"did":        didKey,
		"public_key": json.RawMessage(publicKeyJWK),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

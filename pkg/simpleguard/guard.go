package simpleguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	MaxTokenAge = 60 * time.Second
)

// SimpleGuard handles A2A security enforcement.
type SimpleGuard struct {
	config Config
	signer jose.Signer
}

// New creates a new SimpleGuard instance.
func New(cfg Config) (*SimpleGuard, error) {
	// Auto-generate keys in DevMode if missing
	if cfg.DevMode && (cfg.PrivateKey == nil || cfg.PublicKey == nil) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate dev keys: %w", err)
		}
		cfg.PublicKey = pub
		cfg.PrivateKey = priv
		if cfg.KeyID == "" {
			cfg.KeyID = "dev-key"
		}
		if cfg.AgentID == "" {
			cfg.AgentID = "dev-agent"
		}
	}

	// Create signer
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader("kid", cfg.KeyID)

	// Assuming Ed25519 for now as per Python SDK parity
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: cfg.PrivateKey}, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &SimpleGuard{
		config: cfg,
		signer: signer,
	}, nil
}

// SignOutbound creates a signed JWS for the given payload and body.
// It enforces iat and exp to prevent backdating.
func (g *SimpleGuard) SignOutbound(claims Claims, body []byte) (string, error) {
	now := time.Now()
	
	// Enforce timestamps
	claims.IssuedAt = now.Unix()
	claims.Expiry = now.Add(MaxTokenAge).Unix()
	claims.Issuer = g.config.AgentID

	// Calculate body hash if body is present
	if len(body) > 0 {
		hash := sha256.Sum256(body)
		claims.BodyHash = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	// Marshal claims
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Sign
	jwsObj, err := g.signer.Sign(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %w", err)
	}

	return jwsObj.CompactSerialize()
}

// VerifyInbound validates a received JWS token.
func (g *SimpleGuard) VerifyInbound(token string, body []byte) (*Claims, error) {
	// 1. Parse JWS
	jwsObj, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// 2. Verify Signature
	// In a real scenario, we'd look up the key based on the 'kid' header.
	// For SimpleGuard parity (often used in dev/p2p where we know the peer or trust our own key for testing),
	// we'll use the configured PublicKey. 
	// TODO: Add support for a KeyResolver or TrustedKeys map.
	payload, err := jwsObj.Verify(g.config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	// 3. Unmarshal Claims
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// 4. Verify Timestamps
	now := time.Now().Unix()
	
	// Check Expiry
	if claims.Expiry < now {
		return nil, ErrTokenExpired
	}

	// Check IssuedAt (allow some clock skew, e.g., 5 seconds future)
	if claims.IssuedAt > now+5 {
		return nil, ErrTokenFuture
	}

	// Check Age (redundant with exp but good for sanity)
	if now-claims.IssuedAt > int64(MaxTokenAge.Seconds())+5 {
		return nil, ErrTokenExpired
	}

	// 5. Verify Integrity (Body Hash)
	if len(body) > 0 {
		if claims.BodyHash == "" {
			return nil, fmt.Errorf("%w: missing bh claim for body", ErrIntegrityFailed)
		}
		
		hash := sha256.Sum256(body)
		expectedHash := base64.RawURLEncoding.EncodeToString(hash[:])
		
		if claims.BodyHash != expectedHash {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrIntegrityFailed, expectedHash, claims.BodyHash)
		}
	} else if claims.BodyHash != "" {
		// Body is empty but claim has hash? 
		// Technically valid if hash is of empty string, but usually implies mismatch.
		// Let's check hash of empty string.
		hash := sha256.Sum256([]byte{})
		emptyHash := base64.RawURLEncoding.EncodeToString(hash[:])
		if claims.BodyHash != emptyHash {
			return nil, fmt.Errorf("%w: body is empty but bh claim does not match empty hash", ErrIntegrityFailed)
		}
	}

	return &claims, nil
}

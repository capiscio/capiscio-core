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

// MaxTokenAge is kept for backward compatibility. Use Config.MaxTokenAge instead.
// Deprecated: Use DefaultMaxTokenAge or Config.MaxTokenAge.
const MaxTokenAge = 60 * time.Second

// SimpleGuard handles A2A security enforcement.
type SimpleGuard struct {
	config Config
	signer jose.Signer
}

// New creates a new SimpleGuard instance.
func New(cfg Config) (*SimpleGuard, error) {
	// Apply defaults for configurable values
	if cfg.MaxTokenAge == 0 {
		cfg.MaxTokenAge = DefaultMaxTokenAge
	}
	if cfg.ClockSkewTolerance == 0 {
		cfg.ClockSkewTolerance = DefaultClockSkewTolerance
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}

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

	// Validate key type - only Ed25519 is supported
	if cfg.PrivateKey != nil {
		if _, ok := cfg.PrivateKey.(ed25519.PrivateKey); !ok {
			return nil, fmt.Errorf("unsupported private key type: only ed25519.PrivateKey is supported")
		}
	}

	// Create signer
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader("kid", cfg.KeyID)

	// Only Ed25519 keys are supported for signing (as per Python SDK parity)
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

	// Enforce timestamps using configured MaxTokenAge
	claims.IssuedAt = now.Unix()
	claims.Expiry = now.Add(g.config.MaxTokenAge).Unix()
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
	// NOTE: Only a single configured public key is supported for signature verification.
	//       Key rotation and multiple trusted parties are not supported in this version.
	//       Future versions may add support for key resolution via a KeyResolver interface.
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
	clockSkew := int64(g.config.ClockSkewTolerance.Seconds())

	// Check Expiry (reject tokens at or past expiration)
	if claims.Expiry <= now {
		return nil, ErrTokenExpired
	}

	// Check IssuedAt (allow configured clock skew for future timestamps)
	if claims.IssuedAt > now+clockSkew {
		return nil, ErrTokenFuture
	}

	// Check Age (ensure token isn't older than MaxTokenAge + clock skew)
	if now-claims.IssuedAt > int64(g.config.MaxTokenAge.Seconds())+clockSkew {
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
		// Body is empty but bh claim exists - this indicates a mismatch.
		// The token was signed for a request with a body, but we received no body.
		return nil, fmt.Errorf("%w: body is empty but bh claim is present", ErrIntegrityFailed)
	}

	return &claims, nil
}

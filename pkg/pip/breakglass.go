package pip

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// BreakGlassToken represents a break-glass override token (RFC-005 §9).
// Break-glass tokens bypass PDP authorization (not authentication).
type BreakGlassToken struct {
	JTI    string          `json:"jti"`
	IAT    int64           `json:"iat"`
	EXP    int64           `json:"exp"`
	ISS    string          `json:"iss"`    // root admin issuer, NOT an agent DID
	SUB    string          `json:"sub"`    // operator identity
	Scope  BreakGlassScope `json:"scope"`
	Reason string          `json:"reason"` // human-readable justification
}

// BreakGlassScope defines what the override token permits.
type BreakGlassScope struct {
	Methods []string `json:"methods"` // supports "*"
	Routes  []string `json:"routes"`  // supports "*" and prefix matching
}

// BreakGlassValidator validates break-glass override tokens.
type BreakGlassValidator struct {
	// publicKey is the break-glass signing key.
	// MUST be separate from the CA signing key used for badges (§9.2).
	publicKey crypto.PublicKey

	// nowFunc is injectable for testing.
	nowFunc func() time.Time
}

// NewBreakGlassValidator creates a new break-glass validator.
// publicKey MUST be the dedicated break-glass verification key,
// NOT the CA key used for badge signing.
func NewBreakGlassValidator(publicKey crypto.PublicKey) *BreakGlassValidator {
	return &BreakGlassValidator{
		publicKey: publicKey,
		nowFunc:   func() time.Time { return time.Now().UTC() },
	}
}

// ValidateToken validates a break-glass token's claims (not signature — see note).
//
// In production, the token would arrive as a signed JWS. Signature verification
// requires the go-jose library which is already a dependency in pkg/badge.
// This method validates the claims after JWS verification has extracted them.
func (v *BreakGlassValidator) ValidateToken(token *BreakGlassToken) error {
	if token == nil {
		return fmt.Errorf("breakglass: nil token")
	}
	if token.JTI == "" {
		return fmt.Errorf("breakglass: missing jti")
	}
	if token.ISS == "" {
		return fmt.Errorf("breakglass: missing iss")
	}
	if token.SUB == "" {
		return fmt.Errorf("breakglass: missing sub")
	}
	if token.Reason == "" {
		return fmt.Errorf("breakglass: missing reason (required for audit)")
	}

	now := v.nowFunc()

	// Check expiry
	expiresAt := time.Unix(token.EXP, 0)
	if now.After(expiresAt) {
		return fmt.Errorf("breakglass: token expired at %s", expiresAt.Format(time.RFC3339))
	}

	// Check not-before (iat)
	issuedAt := time.Unix(token.IAT, 0)
	if now.Before(issuedAt) {
		return fmt.Errorf("breakglass: token not yet valid (issued at %s)", issuedAt.Format(time.RFC3339))
	}

	return nil
}

// MatchesScope checks if the token's scope covers the given method and route.
// Scope matching rules (§9.2):
// - "*" matches everything
// - Exact match wins
// - Routes support prefix matching
func (v *BreakGlassValidator) MatchesScope(token *BreakGlassToken, method, route string) bool {
	if token == nil {
		return false
	}

	methodMatch := false
	for _, m := range token.Scope.Methods {
		if m == "*" || m == method {
			methodMatch = true
			break
		}
	}
	if !methodMatch {
		return false
	}

	for _, r := range token.Scope.Routes {
		if r == "*" || r == route {
			return true
		}
		// Prefix matching: "/v1/agents" matches "/v1/agents/abc-123"
		if len(r) > 0 && len(route) > len(r) && route[:len(r)] == r {
			return true
		}
	}

	return false
}

// PublicKey returns the configured break-glass public key for external use.
func (v *BreakGlassValidator) PublicKey() crypto.PublicKey {
	return v.publicKey
}

// GenerateTestKey creates an ECDSA P-256 key pair for testing.
// NOT for production use.
func GenerateTestKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// SignTestToken creates a simple signed token for testing purposes.
// Uses ECDSA P-256. NOT a real JWS — for unit tests only.
func SignTestToken(priv *ecdsa.PrivateKey, token *BreakGlassToken) ([]byte, error) {
	payload, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}
	// Return payload + signature concatenated (test format only)
	sig := append(r.Bytes(), s.Bytes()...)
	return append(payload, sig...), nil
}

// VerifyTestSignature verifies the simple test signature format.
// NOT for production — use go-jose JWS verification in production.
func VerifyTestSignature(pub *ecdsa.PublicKey, signed []byte, token *BreakGlassToken) bool {
	payload, err := json.Marshal(token)
	if err != nil {
		return false
	}
	if len(signed) <= len(payload) {
		return false
	}
	sigBytes := signed[len(payload):]
	hash := sha256.Sum256(payload)
	half := len(sigBytes) / 2
	r := new(big.Int).SetBytes(sigBytes[:half])
	s := new(big.Int).SetBytes(sigBytes[half:])
	return ecdsa.Verify(pub, hash[:], r, s)
}

package simpleguard

import (
	"crypto"
	"errors"
	"time"
)

// Default configuration values.
const (
	// DefaultMaxTokenAge is the default token validity window (60 seconds).
	// This can be overridden via Config.MaxTokenAge.
	DefaultMaxTokenAge = 60 * time.Second

	// DefaultClockSkewTolerance is the allowed clock drift between parties (5 seconds).
	// This accounts for minor time synchronization differences between systems.
	DefaultClockSkewTolerance = 5 * time.Second

	// DefaultMaxBodySize is the maximum request body size for middleware (10MB).
	// Requests larger than this will be rejected to prevent memory exhaustion.
	DefaultMaxBodySize = 10 << 20 // 10MB
)

// Claims represents the JWT claims for SimpleGuard.
type Claims struct {
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	IssuedAt  int64  `json:"iat"`
	Expiry    int64  `json:"exp"`
	BodyHash  string `json:"bh,omitempty"`
	MessageID string `json:"jti,omitempty"`
}

// Config holds configuration for SimpleGuard.
type Config struct {
	AgentID    string
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	KeyID      string // kid for the header
	DevMode    bool   // If true, allows self-signed/generated keys

	// MaxTokenAge is the token validity window. Defaults to DefaultMaxTokenAge (60s).
	MaxTokenAge time.Duration

	// ClockSkewTolerance is the allowed clock drift. Defaults to DefaultClockSkewTolerance (5s).
	ClockSkewTolerance time.Duration

	// MaxBodySize is the maximum request body size for middleware. Defaults to DefaultMaxBodySize (10MB).
	MaxBodySize int64
}

var (
	ErrMissingHeader    = errors.New("missing X-Capiscio-JWS header")
	ErrInvalidToken     = errors.New("invalid token format")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenFuture      = errors.New("token issued in the future")
	ErrIntegrityFailed  = errors.New("integrity check failed (body hash mismatch)")
	ErrMissingKeyID     = errors.New("missing kid header")
	ErrUntrustedKey     = errors.New("untrusted key ID")
	ErrSignatureInvalid = errors.New("signature verification failed")
)

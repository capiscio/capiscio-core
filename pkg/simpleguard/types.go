package simpleguard

import (
	"crypto"
	"errors"
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

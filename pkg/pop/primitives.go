// Package pop provides shared Proof of Possession cryptographic primitives.
//
// These primitives are used by:
// - RFC-003: Badge issuance PoP (agent proves key to CA)
// - RFC-007: MCP server identity PoP (server proves key to client)
//
// The package extracts common operations to avoid duplication:
// - Nonce generation
// - JWS proof signing
// - Proof verification
// - DID document key extraction
package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// =============================================================================
// Errors
// =============================================================================

var (
	ErrNonceGeneration    = errors.New("failed to generate nonce")
	ErrNonceMismatch      = errors.New("nonce does not match")
	ErrSignatureInvalid   = errors.New("signature verification failed")
	ErrChallengeExpired   = errors.New("challenge has expired")
	ErrInvalidPrivateKey  = errors.New("invalid private key")
	ErrUnsupportedKeyType = errors.New("unsupported key type")
)

// =============================================================================
// Challenge/Response Types
// =============================================================================

// Challenge represents a PoP challenge (nonce + metadata)
// Used by both RFC-003 and RFC-007
type Challenge struct {
	// Nonce is the random challenge value (base64url encoded, no padding)
	Nonce string `json:"nonce"`

	// CreatedAt is when the challenge was created
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the challenge expires
	ExpiresAt time.Time `json:"expires_at"`

	// SubjectDID is the DID being challenged to prove key ownership
	SubjectDID string `json:"subject_did"`
}

// Response represents a PoP response (signature over nonce)
type Response struct {
	// Nonce echoed from challenge
	Nonce string `json:"nonce"`

	// Signature is JWS compact serialization over nonce
	Signature string `json:"signature"`

	// SubjectDID is the responder's DID
	SubjectDID string `json:"subject_did"`
}

// =============================================================================
// Nonce Generation
// =============================================================================

// DefaultNonceSize is 32 bytes (256 bits of entropy)
const DefaultNonceSize = 32

// GenerateNonce creates a cryptographically secure random nonce
// Returns base64url-encoded string (no padding per RFC-003 §6.2)
func GenerateNonce(size int) (string, error) {
	if size <= 0 {
		size = DefaultNonceSize
	}

	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("%w: %v", ErrNonceGeneration, err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// NewChallenge creates a PoP challenge with the given TTL
func NewChallenge(subjectDID string, ttl time.Duration) (*Challenge, error) {
	nonce, err := GenerateNonce(DefaultNonceSize)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &Challenge{
		Nonce:      nonce,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		SubjectDID: subjectDID,
	}, nil
}

// IsExpired checks if the challenge has expired
func (c *Challenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// =============================================================================
// Proof Signing (for responders)
// =============================================================================

// SignNonce signs a nonce with an Ed25519 private key
// Returns JWS compact serialization
//
// This is used by:
// - RFC-003: Agent signing PoP proof for CA
// - RFC-007: MCP server signing nonce for client verification
func SignNonce(nonce string, privateKey ed25519.PrivateKey, keyID string) (string, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return "", ErrInvalidPrivateKey
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey},
		(&jose.SignerOptions{}).
			WithType("pop+jws").
			WithHeader(jose.HeaderKey("kid"), keyID),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	jws, err := signer.Sign([]byte(nonce))
	if err != nil {
		return "", fmt.Errorf("failed to sign nonce: %w", err)
	}

	return jws.CompactSerialize()
}

// CreateResponse creates a complete PoP response by signing the challenge nonce
func CreateResponse(challenge *Challenge, privateKey ed25519.PrivateKey, keyID string) (*Response, error) {
	signature, err := SignNonce(challenge.Nonce, privateKey, keyID)
	if err != nil {
		return nil, err
	}

	return &Response{
		Nonce:      challenge.Nonce,
		Signature:  signature,
		SubjectDID: challenge.SubjectDID,
	}, nil
}

// =============================================================================
// Proof Verification (for challengers)
// =============================================================================

// VerifySignature verifies a JWS signature over a nonce using an Ed25519 public key
//
// This is used by:
// - RFC-003: CA verifying agent PoP proof
// - RFC-007: Client verifying MCP server PoP response
func VerifySignature(signatureJWS string, expectedNonce string, publicKey ed25519.PublicKey) error {
	jws, err := jose.ParseSigned(signatureJWS, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return fmt.Errorf("failed to parse JWS: %w", err)
	}

	payload, err := jws.Verify(publicKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	if string(payload) != expectedNonce {
		return ErrNonceMismatch
	}

	return nil
}

// VerifyResponse verifies a PoP response against a challenge
func VerifyResponse(challenge *Challenge, response *Response, publicKey ed25519.PublicKey) error {
	// Check expiry
	if challenge.IsExpired() {
		return ErrChallengeExpired
	}

	// Check nonce matches
	if response.Nonce != challenge.Nonce {
		return ErrNonceMismatch
	}

	// Verify signature
	return VerifySignature(response.Signature, challenge.Nonce, publicKey)
}

// =============================================================================
// JWK/DID Key Utilities
// =============================================================================

// JWK represents a JSON Web Key (minimal for Ed25519)
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid,omitempty"`
}

// DecodeJWKPublicKey decodes an Ed25519 public key from JWK format
func DecodeJWKPublicKey(jwk *JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, ErrUnsupportedKeyType
	}

	decoded, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK X value: %w", err)
	}

	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key size: %d", len(decoded))
	}

	return ed25519.PublicKey(decoded), nil
}

// EncodeJWKPublicKey encodes an Ed25519 public key to JWK format
func EncodeJWKPublicKey(publicKey ed25519.PublicKey, keyID string) *JWK {
	return &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(publicKey),
		Kid: keyID,
	}
}

// DecodeMultibaseKey decodes a multibase-encoded public key
// Supports 'z' (base58btc) prefix for Ed25519VerificationKey2020
func DecodeMultibaseKey(multibase string) (ed25519.PublicKey, error) {
	if len(multibase) == 0 {
		return nil, errors.New("empty multibase value")
	}

	// 'z' prefix = base58btc
	if multibase[0] != 'z' {
		return nil, fmt.Errorf("unsupported multibase prefix: %c", multibase[0])
	}

	decoded, err := base58Decode(multibase[1:])
	if err != nil {
		return nil, err
	}

	// Check for multicodec prefix (0xed01 = Ed25519 public key)
	if len(decoded) >= 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
		return ed25519.PublicKey(decoded[2:]), nil
	}

	// Or raw key
	if len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}

	return nil, fmt.Errorf("unexpected key length: %d", len(decoded))
}

// =============================================================================
// MCP-specific PoP Extensions (RFC-007)
// =============================================================================

// MCPPoPRequest represents PoP data sent by client in initialize request _meta
// RFC-007: Embedded in MCP handshake, not separate endpoint
type MCPPoPRequest struct {
	// ClientNonce is the challenge nonce for server to sign
	ClientNonce string `json:"client_nonce"`

	// CreatedAt is when the nonce was generated
	CreatedAt time.Time `json:"created_at"`
}

// MCPPoPResponse represents PoP data returned by server in initialize response _meta
// RFC-007: Server proves key ownership within handshake
type MCPPoPResponse struct {
	// NonceSignature is JWS over client_nonce, signed with server's DID key
	NonceSignature string `json:"nonce_signature"`

	// SignedAt is when the signature was created
	SignedAt time.Time `json:"signed_at"`
}

// NewMCPPoPRequest creates a PoP request for MCP initialize
func NewMCPPoPRequest() (*MCPPoPRequest, error) {
	nonce, err := GenerateNonce(DefaultNonceSize)
	if err != nil {
		return nil, err
	}

	return &MCPPoPRequest{
		ClientNonce: nonce,
		CreatedAt:   time.Now(),
	}, nil
}

// CreateMCPPoPResponse creates a PoP response for MCP initialize
// Used by MCP servers to prove key ownership
func CreateMCPPoPResponse(clientNonce string, privateKey ed25519.PrivateKey, keyID string) (*MCPPoPResponse, error) {
	signature, err := SignNonce(clientNonce, privateKey, keyID)
	if err != nil {
		return nil, err
	}

	return &MCPPoPResponse{
		NonceSignature: signature,
		SignedAt:       time.Now(),
	}, nil
}

// VerifyMCPPoPResponse verifies MCP server's PoP response
// Used by clients to verify server identity within handshake
func VerifyMCPPoPResponse(request *MCPPoPRequest, response *MCPPoPResponse, publicKey ed25519.PublicKey, maxAge time.Duration) error {
	// Check request age (optional, for replay protection)
	if maxAge > 0 && time.Since(request.CreatedAt) > maxAge {
		return ErrChallengeExpired
	}

	// Verify signature over client nonce
	return VerifySignature(response.NonceSignature, request.ClientNonce, publicKey)
}

// =============================================================================
// Base58 Decoding (Bitcoin alphabet)
// =============================================================================

func base58Decode(input string) ([]byte, error) {
	const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	if len(input) == 0 {
		return nil, nil
	}

	alphabetMap := make(map[rune]int)
	for i, c := range base58Alphabet {
		alphabetMap[c] = i
	}

	leadingOnes := 0
	for _, c := range input {
		if c != '1' {
			break
		}
		leadingOnes++
	}

	size := len(input)*733/1000 + 1
	buf := make([]byte, size)

	var length int
	for _, c := range input {
		val, ok := alphabetMap[c]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}

		carry := val
		for i := 0; i < length || carry != 0; i++ {
			if i < length {
				carry += 58 * int(buf[i])
			}
			buf[i] = byte(carry % 256)
			carry /= 256
			if i >= length {
				length = i + 1
			}
		}
	}

	result := make([]byte, leadingOnes+length)
	for i := 0; i < leadingOnes; i++ {
		result[i] = 0
	}
	for i := 0; i < length; i++ {
		result[leadingOnes+i] = buf[length-1-i]
	}

	return result, nil
}

// =============================================================================
// JSON helpers for _meta embedding
// =============================================================================

// ToMeta serializes PoP request for MCP _meta
func (r *MCPPoPRequest) ToMeta() map[string]interface{} {
	return map[string]interface{}{
		"capiscio_pop_nonce":      r.ClientNonce,
		"capiscio_pop_created_at": r.CreatedAt.Unix(),
	}
}

// ParseMCPPoPRequestFromMeta extracts PoP request from MCP _meta
func ParseMCPPoPRequestFromMeta(meta map[string]interface{}) *MCPPoPRequest {
	if meta == nil {
		return nil
	}

	nonce, ok := meta["capiscio_pop_nonce"].(string)
	if !ok || nonce == "" {
		return nil
	}

	req := &MCPPoPRequest{
		ClientNonce: nonce,
		CreatedAt:   time.Now(), // Default if not provided
	}

	if ts, ok := meta["capiscio_pop_created_at"].(float64); ok {
		req.CreatedAt = time.Unix(int64(ts), 0)
	}

	return req
}

// ToMeta serializes PoP response for MCP _meta
func (r *MCPPoPResponse) ToMeta() map[string]interface{} {
	return map[string]interface{}{
		"capiscio_pop_signature": r.NonceSignature,
		"capiscio_pop_signed_at": r.SignedAt.Unix(),
	}
}

// ParseMCPPoPResponseFromMeta extracts PoP response from MCP _meta
func ParseMCPPoPResponseFromMeta(meta map[string]interface{}) *MCPPoPResponse {
	if meta == nil {
		return nil
	}

	sig, ok := meta["capiscio_pop_signature"].(string)
	if !ok || sig == "" {
		return nil
	}

	resp := &MCPPoPResponse{
		NonceSignature: sig,
		SignedAt:       time.Now(), // Default if not provided
	}

	if ts, ok := meta["capiscio_pop_signed_at"].(float64); ok {
		resp.SignedAt = time.Unix(int64(ts), 0)
	}

	return resp
}

// =============================================================================
// JSON serialization for Challenge/Response
// =============================================================================

// MarshalJSON implements json.Marshaler
func (c *Challenge) MarshalJSON() ([]byte, error) {
	type alias Challenge
	return json.Marshal((*alias)(c))
}

// UnmarshalJSON implements json.Unmarshaler
func (c *Challenge) UnmarshalJSON(data []byte) error {
	type alias Challenge
	return json.Unmarshal(data, (*alias)(c))
}

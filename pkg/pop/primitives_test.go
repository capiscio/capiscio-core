package pop

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestGenerateNonce(t *testing.T) {
	// Test default size
	nonce1, err := GenerateNonce(DefaultNonceSize)
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if len(nonce1) == 0 {
		t.Error("GenerateNonce() returned empty nonce")
	}

	// Test that nonces are unique
	nonce2, err := GenerateNonce(DefaultNonceSize)
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if nonce1 == nonce2 {
		t.Error("GenerateNonce() returned duplicate nonces")
	}

	// Test custom size
	nonce3, err := GenerateNonce(64)
	if err != nil {
		t.Fatalf("GenerateNonce(64) error: %v", err)
	}
	// Base64 length is approximately 4/3 * input bytes
	if len(nonce3) < 64 {
		t.Errorf("GenerateNonce(64) length = %d, want >= 64", len(nonce3))
	}

	// Test with zero/negative size defaults to DefaultNonceSize
	nonce4, err := GenerateNonce(0)
	if err != nil {
		t.Fatalf("GenerateNonce(0) error: %v", err)
	}
	if len(nonce4) == 0 {
		t.Error("GenerateNonce(0) should use default size")
	}
}

func TestSignAndVerifyNonce(t *testing.T) {
	// Generate a test key pair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	nonce := "test-nonce-12345"
	keyID := "test-key-1"

	// Sign the nonce
	signedJWS, err := SignNonce(nonce, priv, keyID)
	if err != nil {
		t.Fatalf("SignNonce() error: %v", err)
	}
	if signedJWS == "" {
		t.Error("SignNonce() returned empty JWS")
	}

	// Verify the signature
	err = VerifySignature(signedJWS, nonce, pub)
	if err != nil {
		t.Errorf("VerifySignature() error: %v", err)
	}

	// Test with wrong nonce
	err = VerifySignature(signedJWS, "wrong-nonce", pub)
	if err == nil {
		t.Error("VerifySignature() should fail with wrong nonce")
	}

	// Test with wrong key
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	err = VerifySignature(signedJWS, nonce, wrongPub)
	if err == nil {
		t.Error("VerifySignature() should fail with wrong key")
	}
}

func TestSignNonce_InvalidKey(t *testing.T) {
	invalidKey := ed25519.PrivateKey([]byte("too-short"))
	_, err := SignNonce("nonce", invalidKey, "key-1")
	if err != ErrInvalidPrivateKey {
		t.Errorf("SignNonce with invalid key: got %v, want ErrInvalidPrivateKey", err)
	}
}

func TestVerifySignature_InvalidJWS(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	
	// Invalid JWS format
	err := VerifySignature("not-a-valid-jws", "nonce", pub)
	if err == nil {
		t.Error("VerifySignature should fail with invalid JWS")
	}
}

func TestNewChallenge(t *testing.T) {
	subjectDID := "did:web:example.com:servers:myserver"
	ttl := 5 * time.Minute

	challenge, err := NewChallenge(subjectDID, ttl)
	if err != nil {
		t.Fatalf("NewChallenge() error: %v", err)
	}

	if challenge.SubjectDID != subjectDID {
		t.Errorf("SubjectDID = %q, want %q", challenge.SubjectDID, subjectDID)
	}
	if challenge.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if challenge.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if challenge.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if !challenge.ExpiresAt.After(challenge.CreatedAt) {
		t.Error("ExpiresAt should be after CreatedAt")
	}
}

func TestChallenge_IsExpired(t *testing.T) {
	// Not expired
	challenge, _ := NewChallenge("did:web:example.com", time.Hour)
	if challenge.IsExpired() {
		t.Error("Challenge should not be expired")
	}

	// Manually create expired challenge
	expired := &Challenge{
		Nonce:      "test",
		CreatedAt:  time.Now().Add(-time.Hour),
		ExpiresAt:  time.Now().Add(-time.Minute),
		SubjectDID: "did:web:example.com",
	}
	if !expired.IsExpired() {
		t.Error("Challenge should be expired")
	}
}

func TestCreateResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	challenge, _ := NewChallenge("did:web:example.com", time.Hour)

	response, err := CreateResponse(challenge, priv, "key-1")
	if err != nil {
		t.Fatalf("CreateResponse() error: %v", err)
	}

	if response.Nonce != challenge.Nonce {
		t.Error("Response nonce should match challenge nonce")
	}
	if response.Signature == "" {
		t.Error("Response signature should not be empty")
	}

	// Verify the response
	err = VerifySignature(response.Signature, challenge.Nonce, pub)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestVerifyResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	challenge, _ := NewChallenge("did:web:example.com", time.Hour)
	response, _ := CreateResponse(challenge, priv, "key-1")

	// Valid response
	err := VerifyResponse(challenge, response, pub)
	if err != nil {
		t.Errorf("VerifyResponse() error: %v", err)
	}

	// Expired challenge
	expiredChallenge := &Challenge{
		Nonce:      response.Nonce,
		CreatedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-time.Hour),
		SubjectDID: "did:web:example.com",
	}
	err = VerifyResponse(expiredChallenge, response, pub)
	if err != ErrChallengeExpired {
		t.Errorf("VerifyResponse with expired challenge: got %v, want ErrChallengeExpired", err)
	}

	// Nonce mismatch
	wrongResponse := &Response{
		Nonce:      "different-nonce",
		Signature:  response.Signature,
		SubjectDID: response.SubjectDID,
	}
	err = VerifyResponse(challenge, wrongResponse, pub)
	if err != ErrNonceMismatch {
		t.Errorf("VerifyResponse with wrong nonce: got %v, want ErrNonceMismatch", err)
	}
}

func TestNewMCPPoPRequest(t *testing.T) {
	req, err := NewMCPPoPRequest()
	if err != nil {
		t.Fatalf("NewMCPPoPRequest() error: %v", err)
	}

	if req.ClientNonce == "" {
		t.Error("ClientNonce should not be empty")
	}
	if req.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestMCPPoPRequestToMeta(t *testing.T) {
	req := &MCPPoPRequest{
		ClientNonce: "test-nonce",
		CreatedAt:   time.Now(),
	}

	meta := req.ToMeta()
	if meta == nil {
		t.Fatal("ToMeta() returned nil")
	}

	if meta["capiscio_pop_nonce"] != "test-nonce" {
		t.Errorf("meta[capiscio_pop_nonce] = %q, want %q", meta["capiscio_pop_nonce"], "test-nonce")
	}
	if _, ok := meta["capiscio_pop_created_at"]; !ok {
		t.Errorf("meta should contain capiscio_pop_created_at")
	}
}

func TestParseMCPPoPRequestFromMeta(t *testing.T) {
	now := time.Now()
	meta := map[string]interface{}{
		"capiscio_pop_nonce":      "test-nonce",
		"capiscio_pop_created_at": float64(now.Unix()),
	}

	req := ParseMCPPoPRequestFromMeta(meta)
	if req == nil {
		t.Fatal("ParseMCPPoPRequestFromMeta() returned nil")
	}

	if req.ClientNonce != "test-nonce" {
		t.Errorf("ClientNonce = %q, want %q", req.ClientNonce, "test-nonce")
	}
}

func TestParseMCPPoPRequestFromMeta_Missing(t *testing.T) {
	// Empty meta
	req := ParseMCPPoPRequestFromMeta(map[string]interface{}{})
	if req != nil {
		t.Error("should return nil on empty meta")
	}

	// Nil meta
	req = ParseMCPPoPRequestFromMeta(nil)
	if req != nil {
		t.Error("should return nil on nil meta")
	}

	// Empty nonce
	req = ParseMCPPoPRequestFromMeta(map[string]interface{}{
		"capiscio_pop_nonce": "",
	})
	if req != nil {
		t.Error("should return nil on empty nonce")
	}
}

func TestCreateAndVerifyMCPPoPResponse(t *testing.T) {
	// Generate key pair
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "key-1"

	clientNonce := "test-client-nonce-12345"
	popRequest := &MCPPoPRequest{
		ClientNonce: clientNonce,
		CreatedAt:   time.Now(),
	}

	// Create response
	resp, err := CreateMCPPoPResponse(clientNonce, priv, keyID)
	if err != nil {
		t.Fatalf("CreateMCPPoPResponse() error: %v", err)
	}

	if resp.NonceSignature == "" {
		t.Error("NonceSignature should not be empty")
	}
	if resp.SignedAt.IsZero() {
		t.Error("SignedAt should not be zero")
	}

	// Verify response
	maxAge := time.Minute
	err = VerifyMCPPoPResponse(popRequest, resp, pub, maxAge)
	if err != nil {
		t.Errorf("VerifyMCPPoPResponse() error: %v", err)
	}

	// Test with wrong nonce
	wrongRequest := &MCPPoPRequest{
		ClientNonce: "wrong-nonce",
		CreatedAt:   time.Now(),
	}
	err = VerifyMCPPoPResponse(wrongRequest, resp, pub, maxAge)
	if err == nil {
		t.Error("should fail with wrong nonce")
	}

	// Test with wrong key
	wrongPub, _, _ := ed25519.GenerateKey(nil)
	err = VerifyMCPPoPResponse(popRequest, resp, wrongPub, maxAge)
	if err == nil {
		t.Error("should fail with wrong key")
	}

	// Test expired request
	expiredRequest := &MCPPoPRequest{
		ClientNonce: clientNonce,
		CreatedAt:   time.Now().Add(-2 * time.Minute),
	}
	err = VerifyMCPPoPResponse(expiredRequest, resp, pub, maxAge)
	if err != ErrChallengeExpired {
		t.Errorf("should fail with expired request, got: %v", err)
	}

	// Test with maxAge = 0 (no expiry check)
	err = VerifyMCPPoPResponse(expiredRequest, resp, pub, 0)
	if err != nil {
		t.Errorf("with maxAge=0 should not check expiry: %v", err)
	}
}

func TestMCPPoPResponseToMeta(t *testing.T) {
	resp := &MCPPoPResponse{
		NonceSignature: "test-sig",
		SignedAt:       time.Now(),
	}

	meta := resp.ToMeta()
	if meta == nil {
		t.Fatal("ToMeta() returned nil")
	}

	if meta["capiscio_pop_signature"] != "test-sig" {
		t.Errorf("meta[capiscio_pop_signature] = %q, want %q", meta["capiscio_pop_signature"], "test-sig")
	}
}

func TestParseMCPPoPResponseFromMeta(t *testing.T) {
	now := time.Now()
	meta := map[string]interface{}{
		"capiscio_pop_signature": "test-sig",
		"capiscio_pop_signed_at": float64(now.Unix()),
	}

	resp := ParseMCPPoPResponseFromMeta(meta)
	if resp == nil {
		t.Fatal("ParseMCPPoPResponseFromMeta() returned nil")
	}

	if resp.NonceSignature != "test-sig" {
		t.Errorf("NonceSignature = %q, want %q", resp.NonceSignature, "test-sig")
	}
}

func TestParseMCPPoPResponseFromMeta_Missing(t *testing.T) {
	// Empty meta
	resp := ParseMCPPoPResponseFromMeta(map[string]interface{}{})
	if resp != nil {
		t.Error("should return nil on empty meta")
	}

	// Nil meta
	resp = ParseMCPPoPResponseFromMeta(nil)
	if resp != nil {
		t.Error("should return nil on nil meta")
	}

	// Empty signature
	resp = ParseMCPPoPResponseFromMeta(map[string]interface{}{
		"capiscio_pop_signature": "",
	})
	if resp != nil {
		t.Error("should return nil on empty signature")
	}
}

func TestDecodeJWKPublicKey(t *testing.T) {
	// Generate a key pair
	pub, _, _ := ed25519.GenerateKey(nil)
	
	// Encode to JWK
	jwk := EncodeJWKPublicKey(pub, "test-key")
	
	// Decode back
	decoded, err := DecodeJWKPublicKey(jwk)
	if err != nil {
		t.Fatalf("DecodeJWKPublicKey() error: %v", err)
	}
	
	if string(decoded) != string(pub) {
		t.Error("Decoded key doesn't match original")
	}
}

func TestDecodeJWKPublicKey_Errors(t *testing.T) {
	// Wrong key type
	_, err := DecodeJWKPublicKey(&JWK{Kty: "RSA", Crv: "Ed25519", X: ""})
	if err != ErrUnsupportedKeyType {
		t.Errorf("wrong kty: got %v, want ErrUnsupportedKeyType", err)
	}

	// Wrong curve
	_, err = DecodeJWKPublicKey(&JWK{Kty: "OKP", Crv: "P-256", X: ""})
	if err != ErrUnsupportedKeyType {
		t.Errorf("wrong crv: got %v, want ErrUnsupportedKeyType", err)
	}

	// Invalid base64
	_, err = DecodeJWKPublicKey(&JWK{Kty: "OKP", Crv: "Ed25519", X: "not-valid-base64!!!"})
	if err == nil {
		t.Error("invalid base64 should error")
	}

	// Wrong key size
	_, err = DecodeJWKPublicKey(&JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte("short"))})
	if err == nil {
		t.Error("wrong key size should error")
	}
}

func TestEncodeJWKPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	keyID := "test-key-123"
	
	jwk := EncodeJWKPublicKey(pub, keyID)
	
	if jwk.Kty != "OKP" {
		t.Errorf("Kty = %q, want OKP", jwk.Kty)
	}
	if jwk.Crv != "Ed25519" {
		t.Errorf("Crv = %q, want Ed25519", jwk.Crv)
	}
	if jwk.Kid != keyID {
		t.Errorf("Kid = %q, want %q", jwk.Kid, keyID)
	}
	if jwk.X == "" {
		t.Error("X should not be empty")
	}
}

func TestDecodeMultibaseKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	
	// Test with multicodec-prefixed key (0xed01 = Ed25519 public key)
	prefixed := append([]byte{0xed, 0x01}, pub...)
	multibase := "z" + base58EncodeSimple(prefixed)
	
	decoded, err := DecodeMultibaseKey(multibase)
	if err != nil {
		t.Fatalf("DecodeMultibaseKey() error: %v", err)
	}
	
	if len(decoded) != len(pub) {
		t.Errorf("Decoded key length %d, want %d", len(decoded), len(pub))
	}
	for i := range pub {
		if decoded[i] != pub[i] {
			t.Errorf("Decoded key byte %d differs", i)
			break
		}
	}
	
	// Test with raw 32-byte key (no multicodec prefix)
	rawMultibase := "z" + base58EncodeSimple(pub)
	decodedRaw, err := DecodeMultibaseKey(rawMultibase)
	if err != nil {
		t.Fatalf("DecodeMultibaseKey(raw) error: %v", err)
	}
	if len(decodedRaw) != ed25519.PublicKeySize {
		t.Errorf("Raw decoded key length %d, want %d", len(decodedRaw), ed25519.PublicKeySize)
	}
}

// base58EncodeSimple for testing (Bitcoin alphabet)
func base58EncodeSimple(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	
	if len(input) == 0 {
		return ""
	}

	// Count leading zeros
	var leadingZeros int
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Convert to big integer and repeatedly divide by 58
	// Use a simple algorithm with byte slice arithmetic
	tmp := make([]byte, len(input))
	copy(tmp, input)

	var result []byte
	for {
		var carry int
		allZero := true
		for i := range tmp {
			carry = carry*256 + int(tmp[i])
			tmp[i] = byte(carry / 58)
			carry = carry % 58
			if tmp[i] != 0 {
				allZero = false
			}
		}
		result = append([]byte{alphabet[carry]}, result...)
		if allZero {
			break
		}
	}

	// Add leading '1's for leading zeros
	for i := 0; i < leadingZeros; i++ {
		result = append([]byte{'1'}, result...)
	}

	return string(result)
}

func TestDecodeMultibaseKey_Errors(t *testing.T) {
	// Empty
	_, err := DecodeMultibaseKey("")
	if err == nil {
		t.Error("empty multibase should error")
	}

	// Wrong prefix
	_, err = DecodeMultibaseKey("m123")
	if err == nil {
		t.Error("wrong prefix should error")
	}

	// Invalid base58
	_, err = DecodeMultibaseKey("z0OIl") // Contains invalid chars
	if err == nil {
		t.Error("invalid base58 should error")
	}
}

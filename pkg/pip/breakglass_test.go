package pip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// generateTestKey creates an ECDSA P-256 key pair for testing.
func generateTestKey() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// signTestToken creates a simple signed token for testing purposes.
// Uses ECDSA P-256 with fixed-width r/s encoding. NOT a real JWS.
func signTestToken(priv *ecdsa.PrivateKey, token *BreakGlassToken) ([]byte, error) {
	payload, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, err
	}
	// Fixed-width encoding: pad r and s to curve byte size (32 bytes for P-256)
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteLen-len(rBytes):byteLen], rBytes)
	copy(sig[2*byteLen-len(sBytes):], sBytes)
	return append(payload, sig...), nil
}

// verifyTestSignature verifies the fixed-width test signature format.
func verifyTestSignature(pub *ecdsa.PublicKey, signed []byte, token *BreakGlassToken) bool {
	payload, err := json.Marshal(token)
	if err != nil {
		return false
	}
	if len(signed) <= len(payload) {
		return false
	}
	sigBytes := signed[len(payload):]
	hash := sha256.Sum256(payload)
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	if len(sigBytes) != 2*byteLen {
		return false
	}
	r := new(big.Int).SetBytes(sigBytes[:byteLen])
	s := new(big.Int).SetBytes(sigBytes[byteLen:])
	return ecdsa.Verify(pub, hash[:], r, s)
}

func TestBreakGlassValidator_ValidToken(t *testing.T) {
	_, pub, err := generateTestKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now().UTC()
	v := NewBreakGlassValidator(pub)
	v.nowFunc = func() time.Time { return now }

	token := &BreakGlassToken{
		JTI:    "bg-001",
		IAT:    now.Add(-1 * time.Minute).Unix(),
		EXP:    now.Add(5 * time.Minute).Unix(),
		ISS:    "admin@example.com",
		SUB:    "ops-engineer-1",
		Scope:  BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
		Reason: "PDP outage — incident INC-4523",
	}

	if err := v.ValidateToken(token); err != nil {
		t.Errorf("valid token rejected: %v", err)
	}
}

func TestBreakGlassValidator_ExpiredToken(t *testing.T) {
	_, pub, _ := generateTestKey()
	now := time.Now().UTC()
	v := NewBreakGlassValidator(pub)
	v.nowFunc = func() time.Time { return now }

	token := &BreakGlassToken{
		JTI:    "bg-002",
		IAT:    now.Add(-10 * time.Minute).Unix(),
		EXP:    now.Add(-5 * time.Minute).Unix(), // expired 5 min ago
		ISS:    "admin@example.com",
		SUB:    "ops-engineer-1",
		Scope:  BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
		Reason: "test",
	}

	if err := v.ValidateToken(token); err == nil {
		t.Error("expired token should be rejected")
	}
}

func TestBreakGlassValidator_FutureToken(t *testing.T) {
	_, pub, _ := generateTestKey()
	now := time.Now().UTC()
	v := NewBreakGlassValidator(pub)
	v.nowFunc = func() time.Time { return now }

	token := &BreakGlassToken{
		JTI:    "bg-003",
		IAT:    now.Add(5 * time.Minute).Unix(), // issued in the future
		EXP:    now.Add(10 * time.Minute).Unix(),
		ISS:    "admin@example.com",
		SUB:    "ops-engineer-1",
		Scope:  BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
		Reason: "test",
	}

	if err := v.ValidateToken(token); err == nil {
		t.Error("future token should be rejected")
	}
}

func TestBreakGlassValidator_MissingFields(t *testing.T) {
	_, pub, _ := generateTestKey()
	v := NewBreakGlassValidator(pub)

	tests := []struct {
		name  string
		token *BreakGlassToken
	}{
		{"nil token", nil},
		{"missing jti", &BreakGlassToken{ISS: "a", SUB: "b", Reason: "r", EXP: time.Now().Add(time.Hour).Unix()}},
		{"missing iss", &BreakGlassToken{JTI: "j", SUB: "b", Reason: "r", EXP: time.Now().Add(time.Hour).Unix()}},
		{"missing sub", &BreakGlassToken{JTI: "j", ISS: "a", Reason: "r", EXP: time.Now().Add(time.Hour).Unix()}},
		{"missing reason", &BreakGlassToken{JTI: "j", ISS: "a", SUB: "b", EXP: time.Now().Add(time.Hour).Unix()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := v.ValidateToken(tt.token); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestBreakGlassValidator_ScopeMatching(t *testing.T) {
	_, pub, _ := generateTestKey()
	v := NewBreakGlassValidator(pub)

	tests := []struct {
		name    string
		scope   BreakGlassScope
		method  string
		route   string
		matches bool
	}{
		{
			name:    "wildcard all",
			scope:   BreakGlassScope{Methods: []string{"*"}, Routes: []string{"*"}},
			method:  "GET",
			route:   "/v1/agents/abc",
			matches: true,
		},
		{
			name:    "exact method and route",
			scope:   BreakGlassScope{Methods: []string{"GET"}, Routes: []string{"/v1/agents/abc"}},
			method:  "GET",
			route:   "/v1/agents/abc",
			matches: true,
		},
		{
			name:    "wrong method",
			scope:   BreakGlassScope{Methods: []string{"POST"}, Routes: []string{"*"}},
			method:  "GET",
			route:   "/v1/agents/abc",
			matches: false,
		},
		{
			name:    "route prefix match",
			scope:   BreakGlassScope{Methods: []string{"*"}, Routes: []string{"/v1/agents"}},
			method:  "GET",
			route:   "/v1/agents/abc-123",
			matches: true,
		},
		{
			name:    "route no prefix match",
			scope:   BreakGlassScope{Methods: []string{"*"}, Routes: []string{"/v1/badges"}},
			method:  "GET",
			route:   "/v1/agents/abc",
			matches: false,
		},
		{
			name:    "route prefix without path boundary",
			scope:   BreakGlassScope{Methods: []string{"*"}, Routes: []string{"/v1/agents"}},
			method:  "GET",
			route:   "/v1/agentsX",
			matches: false,
		},
		{
			name:    "multiple methods — one matches",
			scope:   BreakGlassScope{Methods: []string{"GET", "POST"}, Routes: []string{"*"}},
			method:  "POST",
			route:   "/v1/test",
			matches: true,
		},
		{
			name:    "multiple routes — one matches",
			scope:   BreakGlassScope{Methods: []string{"*"}, Routes: []string{"/v1/agents", "/v1/badges"}},
			method:  "GET",
			route:   "/v1/badges/xyz",
			matches: true,
		},
		{
			name:    "empty methods — no match",
			scope:   BreakGlassScope{Methods: []string{}, Routes: []string{"*"}},
			method:  "GET",
			route:   "/v1/test",
			matches: false,
		},
		{
			name:    "empty routes — no match",
			scope:   BreakGlassScope{Methods: []string{"*"}, Routes: []string{}},
			method:  "GET",
			route:   "/v1/test",
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &BreakGlassToken{Scope: tt.scope}
			got := v.MatchesScope(token, tt.method, tt.route)
			if got != tt.matches {
				t.Errorf("MatchesScope(method=%q, route=%q) = %v, want %v", tt.method, tt.route, got, tt.matches)
			}
		})
	}
}

func TestBreakGlassValidator_NilTokenScope(t *testing.T) {
	_, pub, _ := generateTestKey()
	v := NewBreakGlassValidator(pub)

	if v.MatchesScope(nil, "GET", "/test") {
		t.Error("nil token should never match scope")
	}
}

func TestBreakGlassValidator_PublicKey(t *testing.T) {
	_, pub, _ := generateTestKey()
	v := NewBreakGlassValidator(pub)

	if v.PublicKey() != pub {
		t.Error("PublicKey() should return the configured key")
	}
}

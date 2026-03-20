package pip

import (
	"testing"
	"time"
)

func TestBreakGlassValidator_ValidToken(t *testing.T) {
	_, pub, err := GenerateTestKey()
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
	_, pub, _ := GenerateTestKey()
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
	_, pub, _ := GenerateTestKey()
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
	_, pub, _ := GenerateTestKey()
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
	_, pub, _ := GenerateTestKey()
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
	_, pub, _ := GenerateTestKey()
	v := NewBreakGlassValidator(pub)

	if v.MatchesScope(nil, "GET", "/test") {
		t.Error("nil token should never match scope")
	}
}

func TestBreakGlassValidator_PublicKey(t *testing.T) {
	_, pub, _ := GenerateTestKey()
	v := NewBreakGlassValidator(pub)

	if v.PublicKey() != pub {
		t.Error("PublicKey() should return the configured key")
	}
}

package pip

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
)

// mockHandler is a test obligation handler.
type mockHandler struct {
	supportedType string
	handleErr     error
	called        bool
}

func (m *mockHandler) Handle(ctx context.Context, ob Obligation) error {
	m.called = true
	return m.handleErr
}

func (m *mockHandler) Supports(obligationType string) bool {
	return obligationType == m.supportedType
}

func newMockHandler(t string, err error) *mockHandler {
	return &mockHandler{supportedType: t, handleErr: err}
}

func TestObligationRegistry_EMObserve(t *testing.T) {
	logger := slog.Default()
	reg := NewObligationRegistry(logger)

	knownHandler := newMockHandler("rate_limit", nil)
	reg.Register(knownHandler)

	obligations := []Obligation{
		{Type: "rate_limit", Params: json.RawMessage(`{}`)},
		{Type: "unknown_thing", Params: json.RawMessage(`{}`)},
	}

	result := reg.Enforce(context.Background(), EMObserve, obligations)

	// EM-OBSERVE: always proceed, never enforce
	if !result.Proceed {
		t.Error("EM-OBSERVE should always proceed")
	}
	if knownHandler.called {
		t.Error("EM-OBSERVE should NOT call handler (log only)")
	}
}

func TestObligationRegistry_EMGuard_KnownSuccess(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("rate_limit", nil)
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMGuard, []Obligation{
		{Type: "rate_limit"},
	})

	if !result.Proceed {
		t.Error("EM-GUARD with successful known obligation should proceed")
	}
	if !handler.called {
		t.Error("EM-GUARD should attempt known obligation (best-effort)")
	}
}

func TestObligationRegistry_EMGuard_KnownFailure(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("rate_limit", fmt.Errorf("redis down"))
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMGuard, []Obligation{
		{Type: "rate_limit"},
	})

	// EM-GUARD: best-effort, don't block on failure
	if !result.Proceed {
		t.Error("EM-GUARD should proceed even on known obligation failure")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if !result.Errors[0].Known {
		t.Error("error should be marked as known")
	}
}

func TestObligationRegistry_EMGuard_Unknown(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())

	result := reg.Enforce(context.Background(), EMGuard, []Obligation{
		{Type: "unknown_obligation"},
	})

	// EM-GUARD: skip unknown
	if !result.Proceed {
		t.Error("EM-GUARD should proceed with unknown obligation (skip)")
	}
}

func TestObligationRegistry_EMDelegate_KnownSuccess(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("enhanced_logging", nil)
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMDelegate, []Obligation{
		{Type: "enhanced_logging"},
	})

	if !result.Proceed {
		t.Error("EM-DELEGATE with successful obligation should proceed")
	}
	if !handler.called {
		t.Error("EM-DELEGATE MUST attempt known obligations")
	}
}

func TestObligationRegistry_EMDelegate_KnownFailure(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("enhanced_logging", fmt.Errorf("log service down"))
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMDelegate, []Obligation{
		{Type: "enhanced_logging"},
	})

	// EM-DELEGATE: log failure but don't block
	if !result.Proceed {
		t.Error("EM-DELEGATE should proceed even on known obligation failure")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestObligationRegistry_EMDelegate_Unknown(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())

	result := reg.Enforce(context.Background(), EMDelegate, []Obligation{
		{Type: "unknown_thing"},
	})

	// EM-DELEGATE: log warning, proceed
	if !result.Proceed {
		t.Error("EM-DELEGATE should proceed with unknown obligation")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error for unknown obligation, got %d", len(result.Errors))
	}
	if result.Errors[0].Known {
		t.Error("error should be marked as unknown")
	}
}

func TestObligationRegistry_EMStrict_KnownSuccess(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("rate_limit", nil)
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMStrict, []Obligation{
		{Type: "rate_limit"},
	})

	if !result.Proceed {
		t.Error("EM-STRICT with successful obligation should proceed")
	}
	if !handler.called {
		t.Error("EM-STRICT MUST enforce known obligations")
	}
}

func TestObligationRegistry_EMStrict_KnownFailure(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("rate_limit", fmt.Errorf("redis unavailable"))
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMStrict, []Obligation{
		{Type: "rate_limit"},
	})

	// EM-STRICT: MUST block on obligation failure
	if result.Proceed {
		t.Error("EM-STRICT MUST NOT proceed when known obligation fails")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestObligationRegistry_EMStrict_Unknown(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())

	result := reg.Enforce(context.Background(), EMStrict, []Obligation{
		{Type: "unknown_obligation"},
	})

	// EM-STRICT: unknown obligation → MUST DENY (§7.3)
	if result.Proceed {
		t.Error("EM-STRICT MUST DENY on unknown obligation")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Known {
		t.Error("error should be marked as unknown")
	}
}

func TestObligationRegistry_EMStrict_MixedKnownAndUnknown(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	handler := newMockHandler("rate_limit", nil)
	reg.Register(handler)

	result := reg.Enforce(context.Background(), EMStrict, []Obligation{
		{Type: "rate_limit"},      // known, will succeed
		{Type: "unknown_thing"},   // unknown → DENY
	})

	if result.Proceed {
		t.Error("EM-STRICT should DENY when any obligation is unknown")
	}
}

func TestObligationRegistry_EmptyObligations(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())

	for _, mode := range []EnforcementMode{EMObserve, EMGuard, EMDelegate, EMStrict} {
		result := reg.Enforce(context.Background(), mode, nil)
		if !result.Proceed {
			t.Errorf("%s with no obligations should proceed", mode)
		}

		result = reg.Enforce(context.Background(), mode, []Obligation{})
		if !result.Proceed {
			t.Errorf("%s with empty obligations should proceed", mode)
		}
	}
}

func TestObligationRegistry_MultipleHandlers(t *testing.T) {
	reg := NewObligationRegistry(slog.Default())
	h1 := newMockHandler("rate_limit", nil)
	h2 := newMockHandler("enhanced_logging", nil)
	reg.Register(h1)
	reg.Register(h2)

	result := reg.Enforce(context.Background(), EMStrict, []Obligation{
		{Type: "rate_limit"},
		{Type: "enhanced_logging"},
	})

	if !result.Proceed {
		t.Error("both known obligations succeeded, should proceed")
	}
	if !h1.called || !h2.called {
		t.Error("both handlers should have been called")
	}
}

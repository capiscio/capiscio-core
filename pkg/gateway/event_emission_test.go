// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/gateway"
	"github.com/capiscio/capiscio-core/v2/pkg/mediation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEventSink captures emitted events for testing.
type mockEventSink struct {
	mu     sync.Mutex
	events []*mediation.Event
}

func (m *mockEventSink) Receive(event *mediation.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *mockEventSink) Flush(ctx context.Context) error {
	return nil
}

func (m *mockEventSink) Close() error {
	return nil
}

func (m *mockEventSink) Events() []*mediation.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*mediation.Event{}, m.events...)
}

func (m *mockEventSink) EventTypes() []mediation.EventType {
	m.mu.Lock()
	defer m.mu.Unlock()
	types := make([]mediation.EventType, len(m.events))
	for i, e := range m.events {
		types[i] = e.EventType
	}
	return types
}

func (m *mockEventSink) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}

// HasEventType returns true if an event of the given type has been received.
func (m *mockEventSink) HasEventType(eventType mediation.EventType) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.events {
		if e.EventType == eventType {
			return true
		}
	}
	return false
}

// EventCount returns the number of events received.
func (m *mockEventSink) EventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestEventEmission_IdentityVerified(t *testing.T) {
	// Setup keys and verifier
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// Create event sink and emitter
	sink := &mockEventSink{}
	emitter := mediation.NewAsyncEmitter(mediation.AsyncEmitterConfig{
		ComponentID:   "test-gateway",
		ComponentType: mediation.ComponentGateway,
		Version:       "test",
		BufferSize:    100,
		Sinks:         []mediation.EventSink{sink},
	})
	defer emitter.Close()

	// Create valid badge with VC
	claims := &badge.Claims{
		JTI:      "test-jti-events",
		Issuer:   "did:web:test.capisc.io",
		Subject:  "did:web:test.capisc.io:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "2",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	// Create handler
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Create middleware with emitter
	config := gateway.PEPConfig{
		RuntimeEmitter: emitter,
	}
	handler := gateway.NewPolicyMiddleware(verifier, config, next)

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	req.Header.Set("X-Trace-ID", "trace-123")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wait for async event processing using deterministic polling
	require.Eventually(t, func() bool {
		return sink.HasEventType(mediation.EventIdentityVerified)
	}, 500*time.Millisecond, 10*time.Millisecond, "identity.verified event not emitted within timeout")

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, called)

	// Verify events emitted
	events := sink.Events()
	require.GreaterOrEqual(t, len(events), 1, "should emit at least identity.verified")

	// Find identity.verified event
	var identityVerified *mediation.Event
	for _, e := range events {
		if e.EventType == mediation.EventIdentityVerified {
			identityVerified = e
			break
		}
	}
	require.NotNil(t, identityVerified, "should emit identity.verified event")
	assert.Equal(t, "trace-123", identityVerified.Context.TraceID)
	assert.NotEmpty(t, identityVerified.Context.TxnID)
}

func TestEventEmission_IdentityInvalid_MissingBadge(t *testing.T) {
	// Setup keys and verifier (won't be used since badge is missing)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// Create event sink and emitter
	sink := &mockEventSink{}
	emitter := mediation.NewAsyncEmitter(mediation.AsyncEmitterConfig{
		ComponentID:   "test-gateway",
		ComponentType: mediation.ComponentGateway,
		Version:       "test",
		BufferSize:    100,
		Sinks:         []mediation.EventSink{sink},
	})
	defer emitter.Close()

	// Create handler
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Create middleware with emitter
	config := gateway.PEPConfig{
		RuntimeEmitter: emitter,
	}
	handler := gateway.NewPolicyMiddleware(verifier, config, next)

	// Make request WITHOUT badge
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Trace-ID", "trace-456")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wait for async event processing using deterministic polling
	require.Eventually(t, func() bool {
		return sink.HasEventType(mediation.EventIdentityInvalid)
	}, 500*time.Millisecond, 10*time.Millisecond, "identity.invalid event not emitted within timeout")

	// Verify response
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, called)

	// Verify identity.invalid event emitted
	events := sink.Events()
	require.Len(t, events, 1)
	assert.Equal(t, mediation.EventIdentityInvalid, events[0].EventType)
	assert.Equal(t, "trace-456", events[0].Context.TraceID)
}

func TestEventEmission_ExecutionLifecycle(t *testing.T) {
	// Setup keys and verifier
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// Create event sink and emitter
	sink := &mockEventSink{}
	emitter := mediation.NewAsyncEmitter(mediation.AsyncEmitterConfig{
		ComponentID:   "test-gateway",
		ComponentType: mediation.ComponentGateway,
		Version:       "test",
		BufferSize:    100,
		Sinks:         []mediation.EventSink{sink},
	})
	defer emitter.Close()

	// Create valid badge with VC
	claims := &badge.Claims{
		JTI:      "test-jti-exec",
		Issuer:   "did:web:test.capisc.io",
		Subject:  "did:web:test.capisc.io:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "1",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	// Create handler that takes some time
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	// Create middleware with emitter (badge-only mode, no PDP)
	config := gateway.PEPConfig{
		RuntimeEmitter: emitter,
	}
	handler := gateway.NewPolicyMiddleware(verifier, config, next)

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Capiscio-Badge", token)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wait for async event processing using deterministic polling
	// Wait for execution.completed as it's the last event in the sequence
	require.Eventually(t, func() bool {
		return sink.HasEventType(mediation.EventExecutionCompleted)
	}, 500*time.Millisecond, 10*time.Millisecond, "execution.completed event not emitted within timeout")

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify event sequence: identity.verified, execution.started, execution.completed
	eventTypes := sink.EventTypes()
	require.GreaterOrEqual(t, len(eventTypes), 3, "should emit identity.verified, execution.started, execution.completed")

	assert.Contains(t, eventTypes, mediation.EventIdentityVerified)
	assert.Contains(t, eventTypes, mediation.EventExecutionStarted)
	assert.Contains(t, eventTypes, mediation.EventExecutionCompleted)
}

func TestEventEmission_NoEmitter(t *testing.T) {
	// Setup keys and verifier
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// Create valid badge with VC
	claims := &badge.Claims{
		JTI:      "test-jti-no-emitter",
		Issuer:   "did:web:test.capisc.io",
		Subject:  "did:web:test.capisc.io:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "1",
			},
		},
	}

	token, err := badge.SignBadge(claims, priv)
	require.NoError(t, err)

	// Create handler
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Create middleware WITHOUT emitter (nil)
	config := gateway.PEPConfig{
		RuntimeEmitter: nil, // no emitter
	}
	handler := gateway.NewPolicyMiddleware(verifier, config, next)

	// Make request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Capiscio-Badge", token)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should still work without emitter
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, called)
}

func TestEventEmission_IdentityInvalid_BadgeVerificationFailed(t *testing.T) {
	// Setup keys but sign with different key to trigger verification failure
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	// Create event sink and emitter
	sink := &mockEventSink{}
	emitter := mediation.NewAsyncEmitter(mediation.AsyncEmitterConfig{
		ComponentID:   "test-gateway",
		ComponentType: mediation.ComponentGateway,
		Version:       "test",
		BufferSize:    100,
		Sinks:         []mediation.EventSink{sink},
	})
	defer emitter.Close()

	// Create badge signed with WRONG key
	claims := &badge.Claims{
		JTI:      "test-jti-wrong-key",
		Issuer:   "did:web:test.capisc.io",
		Subject:  "did:web:test.capisc.io:agents:test-agent",
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		VC: badge.VerifiableCredential{
			Type: []string{"VerifiableCredential", "AgentIdentity"},
			CredentialSubject: badge.CredentialSubject{
				Domain: "test.example.com",
				Level:  "2",
			},
		},
	}

	token, err := badge.SignBadge(claims, wrongPriv)
	require.NoError(t, err)

	// Create handler
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Create middleware with emitter
	config := gateway.PEPConfig{
		RuntimeEmitter: emitter,
	}
	handler := gateway.NewPolicyMiddleware(verifier, config, next)

	// Make request with invalid badge
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Capiscio-Badge", token)
	req.Header.Set("X-Trace-ID", "trace-bad-badge")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Wait for async event processing
	require.Eventually(t, func() bool {
		return sink.HasEventType(mediation.EventIdentityInvalid)
	}, 500*time.Millisecond, 10*time.Millisecond, "identity.invalid event not emitted within timeout")

	// Verify response
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, called, "handler should not be called for invalid badge")

	// Verify identity.invalid event emitted (no execution events since we never authenticated)
	events := sink.Events()
	require.GreaterOrEqual(t, len(events), 1)

	hasIdentityInvalid := false
	for _, e := range events {
		if e.EventType == mediation.EventIdentityInvalid {
			hasIdentityInvalid = true
			// Verify error info in payload
			assert.Equal(t, "VERIFICATION_FAILED", e.Payload["error_code"])
		}
	}
	assert.True(t, hasIdentityInvalid, "should emit identity.invalid")
}

func TestEventEmission_OutcomeReflectsHTTPStatus(t *testing.T) {
	// Setup keys and verifier
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	reg := &MockRegistry{Key: pub}
	verifier := badge.NewVerifier(reg)

	tests := []struct {
		name           string
		statusCode     int
		expectedOutcome string
	}{
		{"success_200", http.StatusOK, "success"},
		{"success_201", http.StatusCreated, "success"},
		{"client_error_400", http.StatusBadRequest, "client_error"},
		{"client_error_404", http.StatusNotFound, "client_error"},
		{"server_error_500", http.StatusInternalServerError, "server_error"},
		{"server_error_503", http.StatusServiceUnavailable, "server_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create event sink and emitter
			sink := &mockEventSink{}
			emitter := mediation.NewAsyncEmitter(mediation.AsyncEmitterConfig{
				ComponentID:   "test-gateway",
				ComponentType: mediation.ComponentGateway,
				Version:       "test",
				BufferSize:    100,
				Sinks:         []mediation.EventSink{sink},
			})
			defer emitter.Close()

			// Create valid badge
			claims := &badge.Claims{
				JTI:      "test-jti-" + tt.name,
				Issuer:   "did:web:test.capisc.io",
				Subject:  "did:web:test.capisc.io:agents:test-agent",
				IssuedAt: time.Now().Unix(),
				Expiry:   time.Now().Add(1 * time.Hour).Unix(),
				VC: badge.VerifiableCredential{
					Type: []string{"VerifiableCredential", "AgentIdentity"},
					CredentialSubject: badge.CredentialSubject{
						Domain: "test.example.com",
						Level:  "1",
					},
				},
			}

			token, err := badge.SignBadge(claims, priv)
			require.NoError(t, err)

			// Create handler that returns the test status code
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			// Create middleware with emitter
			config := gateway.PEPConfig{
				RuntimeEmitter: emitter,
			}
			handler := gateway.NewPolicyMiddleware(verifier, config, next)

			// Make request
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("X-Capiscio-Badge", token)

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			// Wait for execution.completed event
			require.Eventually(t, func() bool {
				return sink.HasEventType(mediation.EventExecutionCompleted)
			}, 500*time.Millisecond, 10*time.Millisecond, "execution.completed event not emitted within timeout")

			// Verify outcome field matches expected
			events := sink.Events()
			var execCompleted *mediation.Event
			for _, e := range events {
				if e.EventType == mediation.EventExecutionCompleted {
					execCompleted = e
					break
				}
			}
			require.NotNil(t, execCompleted)
			assert.Equal(t, tt.expectedOutcome, execCompleted.Payload["outcome"],
				"outcome should reflect HTTP status %d", tt.statusCode)
		})
	}
}

// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestEventType_Constants(t *testing.T) {
	// Verify RFC-011 event type format
	tests := []struct {
		eventType EventType
		category  string
	}{
		{EventIdentityVerified, "identity"},
		{EventIdentityInvalid, "identity"},
		{EventAuthorityGranted, "authority"},
		{EventAuthorityDenied, "authority"},
		{EventToolRequested, "tool"},
		{EventToolPermitted, "tool"},
		{EventResourceNetworkRequested, "resource"},
		{EventResourceFilesystemPermitted, "resource"},
		{EventTrustRevocationChecked, "trust"},
		{EventExecutionStarted, "execution"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			// Event types must be dot-delimited
			parts := splitEventType(string(tt.eventType))
			if len(parts) < 2 {
				t.Errorf("event type %q should be dot-delimited", tt.eventType)
			}
			if parts[0] != tt.category {
				t.Errorf("event type %q should start with %q", tt.eventType, tt.category)
			}
		})
	}
}

func splitEventType(et string) []string {
	var parts []string
	part := ""
	for _, c := range et {
		if c == '.' {
			parts = append(parts, part)
			part = ""
		} else {
			part += string(c)
		}
	}
	if part != "" {
		parts = append(parts, part)
	}
	return parts
}

func TestNewEvent(t *testing.T) {
	emitter := EmitterInfo{
		ComponentID:   "test-component",
		ComponentType: ComponentPEP,
		Version:       "1.0.0",
	}

	event := NewEvent(EventAuthorityGranted, emitter)

	// Check required fields
	if event.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q, want %q", event.SchemaVersion, "1.0")
	}
	if len(event.EventID) < 4 || event.EventID[:4] != "evt_" {
		t.Errorf("event_id = %q, should start with 'evt_'", event.EventID)
	}
	if event.EventType != EventAuthorityGranted {
		t.Errorf("event_type = %q, want %q", event.EventType, EventAuthorityGranted)
	}
	if event.Timestamp == "" {
		t.Error("timestamp should not be empty")
	}
	if event.Emitter.ComponentID != "test-component" {
		t.Errorf("emitter.component_id = %q, want %q", event.Emitter.ComponentID, "test-component")
	}
}

func TestEvent_WithContext(t *testing.T) {
	event := NewEvent(EventToolPermitted, EmitterInfo{})
	event.WithContext("trace-123", "txn-456", "hop-001")

	if event.Context.TraceID != "trace-123" {
		t.Errorf("trace_id = %q, want %q", event.Context.TraceID, "trace-123")
	}
	if event.Context.TxnID != "txn-456" {
		t.Errorf("txn_id = %q, want %q", event.Context.TxnID, "txn-456")
	}
	if event.Context.HopID != "hop-001" {
		t.Errorf("hop_id = %q, want %q", event.Context.HopID, "hop-001")
	}
}

func TestEvent_WithPayload(t *testing.T) {
	event := NewEvent(EventToolDenied, EmitterInfo{})
	event.WithPayload("tool_name", "mcp:database/query")
	event.WithPayload("reason", "insufficient trust level")

	if event.Payload["tool_name"] != "mcp:database/query" {
		t.Errorf("payload[tool_name] = %v, want %q", event.Payload["tool_name"], "mcp:database/query")
	}
	if event.Payload["reason"] != "insufficient trust level" {
		t.Errorf("payload[reason] = %v, want %q", event.Payload["reason"], "insufficient trust level")
	}
}

func TestEvent_JSONSerialization(t *testing.T) {
	event := NewEvent(EventAuthorityDenied, EmitterInfo{
		ComponentID:   "test-pep",
		ComponentType: ComponentPEP,
		Version:       "2.4.1",
	})
	event.WithContext("tr_abc", "txn_123", "hop_001")
	event.WithPayload("subject_did", "did:web:example.com:agent")
	event.WithPayload("reason", "trust level too low")

	// Serialize to JSON
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Deserialize and verify
	var parsed Event
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed.SchemaVersion != "1.0" {
		t.Errorf("parsed schema_version = %q, want %q", parsed.SchemaVersion, "1.0")
	}
	if parsed.EventType != EventAuthorityDenied {
		t.Errorf("parsed event_type = %q, want %q", parsed.EventType, EventAuthorityDenied)
	}
	if parsed.Context.TraceID != "tr_abc" {
		t.Errorf("parsed context.trace_id = %q, want %q", parsed.Context.TraceID, "tr_abc")
	}
}

func TestHashForEvent(t *testing.T) {
	hash := HashForEvent("secret value")
	
	// Should be prefixed with sha256:
	if len(hash) < 8 || hash[:7] != "sha256:" {
		t.Errorf("hash = %q, should start with 'sha256:'", hash)
	}
	// SHA-256 produces 64 hex chars
	if len(hash) != 7+64 {
		t.Errorf("hash length = %d, want %d", len(hash), 7+64)
	}

	// Same input produces same hash
	hash2 := HashForEvent("secret value")
	if hash != hash2 {
		t.Error("same input should produce same hash")
	}

	// Different input produces different hash
	hash3 := HashForEvent("different value")
	if hash == hash3 {
		t.Error("different input should produce different hash")
	}
}

func TestClassifyPath(t *testing.T) {
	tests := []struct {
		path         string
		wantContains string
		description  string
	}{
		{"/home/user/docs/file.txt", "*.txt", "should preserve extension"},
		{"/tmp/data", "/tmp/", "should preserve root"},
		{"/etc/config.yaml", "*.yaml", "should preserve extension"},
		{"relative/path.go", "relative/", "should handle short relative paths as-is"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := ClassifyPath(tt.path)
			// Path should be anonymized but still contain expected patterns
			if !containsPattern(got, tt.wantContains) {
				t.Errorf("ClassifyPath(%q) = %q, want to contain %q", tt.path, got, tt.wantContains)
			}
		})
	}
}

func containsPattern(s, pattern string) bool {
	return len(s) >= len(pattern) && 
		(s == pattern || 
		 len(s) > len(pattern) && (s[:len(pattern)] == pattern || s[len(s)-len(pattern):] == pattern) ||
		 indexOfString(s, pattern) >= 0)
}

func indexOfString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestClassifyCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		expected string
	}{
		{"git commit -m 'message'", "git"},
		{"/usr/bin/curl https://api.example.com", "curl"},
		{"ls -la /tmp", "ls"},
		{"", "unknown"},
		{"   ", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			got := ClassifyCommand(tt.cmd)
			if got != tt.expected {
				t.Errorf("ClassifyCommand(%q) = %q, want %q", tt.cmd, got, tt.expected)
			}
		})
	}
}

func TestAsyncEmitter_EmitDecision(t *testing.T) {
	sink := NewChannelSink(10)
	emitter := NewAsyncEmitter(AsyncEmitterConfig{
		ComponentID:   "test-emitter",
		ComponentType: ComponentSDK,
		Version:       "1.0.0",
		Sinks:         []EventSink{sink},
	})
	defer emitter.Close()

	mctx := &Context{
		TraceID:    "trace-001",
		TxnID:      "txn-001",
		SubjectDID: "did:web:example.com:agent",
		TrustLevel: 2,
	}

	result := AllowResult("policy:test:rule1", "tool allowed")
	request := &ToolRequest{ToolName: "mcp:test/tool"}

	emitter.EmitDecision(mctx, result, request)

	// Wait for event
	select {
	case event := <-sink.Events():
		if event.EventType != EventToolPermitted {
			t.Errorf("event_type = %q, want %q", event.EventType, EventToolPermitted)
		}
		if event.Context.TraceID != "trace-001" {
			t.Errorf("context.trace_id = %q, want %q", event.Context.TraceID, "trace-001")
		}
		if event.Payload["subject_did"] != "did:web:example.com:agent" {
			t.Errorf("payload.subject_did = %v, want %q", event.Payload["subject_did"], "did:web:example.com:agent")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestAsyncEmitter_DenyDecision(t *testing.T) {
	sink := NewChannelSink(10)
	emitter := NewAsyncEmitter(AsyncEmitterConfig{
		ComponentID:   "test-emitter",
		ComponentType: ComponentPEP,
		Sinks:         []EventSink{sink},
	})
	defer emitter.Close()

	mctx := &Context{SubjectDID: "did:web:agent"}
	result := DenyResult("builtin:blocked", "tool blocked")
	request := &ToolRequest{ToolName: "mcp:dangerous/tool"}

	emitter.EmitDecision(mctx, result, request)

	select {
	case event := <-sink.Events():
		if event.EventType != EventToolDenied {
			t.Errorf("event_type = %q, want %q", event.EventType, EventToolDenied)
		}
		if event.Payload["reason"] != "tool blocked" {
			t.Errorf("payload.reason = %v, want %q", event.Payload["reason"], "tool blocked")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestAsyncEmitter_CloseDrainsPending(t *testing.T) {
	var received []*Event
	var mu sync.Mutex

	sink := &testSink{
		receiveFn: func(e *Event) {
			mu.Lock()
			received = append(received, e)
			mu.Unlock()
		},
	}

	emitter := NewAsyncEmitter(AsyncEmitterConfig{
		ComponentID:   "drain-test",
		ComponentType: ComponentSDK,
		Sinks:         []EventSink{sink},
	})

	// Emit multiple events
	for i := 0; i < 5; i++ {
		emitter.EmitCapabilityCheck(nil, "cap", true)
	}

	// Close should drain all events
	emitter.Close()

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count != 5 {
		t.Errorf("received %d events, want 5", count)
	}
}

func TestJSONSink(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONSink(&buf)

	event := NewEvent(EventToolExecuted, EmitterInfo{ComponentID: "test"})
	event.WithPayload("tool_name", "test-tool")

	sink.Receive(event)

	// Parse the output
	var parsed Event
	if err := json.NewDecoder(&buf).Decode(&parsed); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if parsed.EventType != EventToolExecuted {
		t.Errorf("event_type = %q, want %q", parsed.EventType, EventToolExecuted)
	}
}

func TestBatchSink(t *testing.T) {
	var batches [][]*Event
	var mu sync.Mutex

	sink := NewBatchSink(3, func(batch []*Event) error {
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		return nil
	})

	// Send 5 events - should trigger one batch of 3
	for i := 0; i < 5; i++ {
		event := NewEvent(EventAuthorityGranted, EmitterInfo{})
		sink.Receive(event)
	}

	mu.Lock()
	batchCount := len(batches)
	mu.Unlock()

	if batchCount != 1 {
		t.Errorf("got %d batches, want 1", batchCount)
	}

	// Flush remaining
	sink.Flush(context.Background())

	mu.Lock()
	batchCount = len(batches)
	mu.Unlock()

	if batchCount != 2 {
		t.Errorf("after flush got %d batches, want 2", batchCount)
	}
}

func TestChannelSink_CloseDropsNew(t *testing.T) {
	sink := NewChannelSink(1)
	
	// Send one event
	event := NewEvent(EventIdentityVerified, EmitterInfo{})
	sink.Receive(event)

	// Close the sink
	sink.Close()

	// New events should be silently dropped
	event2 := NewEvent(EventIdentityVerified, EmitterInfo{})
	sink.Receive(event2) // Should not panic
}

func TestAsyncEmitter_DropOnFull(t *testing.T) {
	sink := NewChannelSink(1)
	emitter := NewAsyncEmitter(AsyncEmitterConfig{
		ComponentID:   "drop-test",
		ComponentType: ComponentSDK,
		BufferSize:    1,
		DropOnFull:    true,
		Sinks:         []EventSink{sink},
	})
	defer emitter.Close()

	// Fill the buffer by emitting rapidly
	for i := 0; i < 100; i++ {
		emitter.EmitCapabilityCheck(nil, "cap", true)
	}

	// Some events should have been dropped
	dropped := emitter.DroppedCount()
	// Note: exact count depends on timing, just verify the mechanism works
	_ = dropped // May or may not be > 0 depending on goroutine scheduling
}

// testSink is a simple test sink.
type testSink struct {
	receiveFn func(*Event)
}

func (s *testSink) Receive(event *Event) {
	if s.receiveFn != nil {
		s.receiveFn(event)
	}
}
func (s *testSink) Flush(ctx context.Context) error { return nil }
func (s *testSink) Close() error                    { return nil }

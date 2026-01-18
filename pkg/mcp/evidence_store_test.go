package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalEvidenceStore_Store(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "evidence-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewLocalEvidenceStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Store a record
	record := EvidenceRecord{
		ID:        "test-id-1",
		EventName: "capiscio.tool_invocation",
		AgentDID:  "did:web:example.com:agents:test",
		Target:    "test_tool",
		Decision:  "ALLOW",
		AuthLevel: "BADGE",
		Timestamp: time.Now(),
	}

	err = store.Store(context.Background(), record)
	if err != nil {
		t.Fatalf("failed to store: %v", err)
	}

	// Check file exists
	expectedFn := filepath.Join(tmpDir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	if _, err := os.Stat(expectedFn); os.IsNotExist(err) {
		t.Errorf("evidence file not created: %s", expectedFn)
	}

	// Read content
	content, err := os.ReadFile(expectedFn)
	if err != nil {
		t.Fatalf("failed to read evidence file: %v", err)
	}
	if len(content) == 0 {
		t.Error("evidence file is empty")
	}
}

func TestEvidenceRateLimiter_Basic(t *testing.T) {
	limiter := NewEvidenceRateLimiter(1*time.Second, 3)

	record := EvidenceRecord{
		Target:    "test_tool",
		AgentDID:  "did:web:example.com:agents:test",
		Decision:  "ALLOW",
		AuthLevel: "BADGE",
	}

	// First 3 should pass
	for i := 0; i < 3; i++ {
		if limiter.IsRateLimited(record) {
			t.Errorf("call %d should not be rate limited", i+1)
		}
	}

	// 4th should be rate limited
	if !limiter.IsRateLimited(record) {
		t.Error("4th call should be rate limited")
	}
}

func TestEvidenceRateLimiter_DifferentFingerprints(t *testing.T) {
	limiter := NewEvidenceRateLimiter(1*time.Second, 2)

	record1 := EvidenceRecord{
		Target:    "tool_a",
		AgentDID:  "did:web:example.com:agents:test",
		Decision:  "ALLOW",
		AuthLevel: "BADGE",
	}

	record2 := EvidenceRecord{
		Target:    "tool_b", // Different tool
		AgentDID:  "did:web:example.com:agents:test",
		Decision:  "ALLOW",
		AuthLevel: "BADGE",
	}

	// Both should pass independently
	if limiter.IsRateLimited(record1) {
		t.Error("record1 first call should not be rate limited")
	}
	if limiter.IsRateLimited(record2) {
		t.Error("record2 first call should not be rate limited")
	}
	if limiter.IsRateLimited(record1) {
		t.Error("record1 second call should not be rate limited")
	}
	if limiter.IsRateLimited(record2) {
		t.Error("record2 second call should not be rate limited")
	}

	// Now both should be rate limited
	if !limiter.IsRateLimited(record1) {
		t.Error("record1 third call should be rate limited")
	}
	if !limiter.IsRateLimited(record2) {
		t.Error("record2 third call should be rate limited")
	}
}

func TestEvidenceRateLimiter_WindowReset(t *testing.T) {
	// Very short window for testing
	limiter := NewEvidenceRateLimiter(50*time.Millisecond, 1)

	record := EvidenceRecord{
		Target:    "test_tool",
		AgentDID:  "did:web:example.com:agents:test",
		Decision:  "ALLOW",
		AuthLevel: "BADGE",
	}

	// First call passes
	if limiter.IsRateLimited(record) {
		t.Error("first call should not be rate limited")
	}

	// Second call rate limited
	if !limiter.IsRateLimited(record) {
		t.Error("second call should be rate limited")
	}

	// Wait for window to expire
	time.Sleep(100 * time.Millisecond)

	// Now should pass again (new window)
	if limiter.IsRateLimited(record) {
		t.Error("call after window reset should not be rate limited")
	}
}

func TestNoOpEvidenceStore(t *testing.T) {
	store := &NoOpEvidenceStore{}

	err := store.Store(context.Background(), EvidenceRecord{
		ID: "test",
	})
	if err != nil {
		t.Errorf("NoOpEvidenceStore.Store should not return error: %v", err)
	}
}

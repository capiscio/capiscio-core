package pip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPPDPClient_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		// Verify PIP request can be decoded
		var req DecisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.PIPVersion != PIPVersion {
			t.Errorf("pip_version = %q, want %q", req.PIPVersion, PIPVersion)
		}

		ttl := 60
		resp := DecisionResponse{
			Decision:    DecisionAllow,
			DecisionID:  "test-decision-001",
			Obligations: []Obligation{},
			TTL:         &ttl,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout, WithPEPID("test-pep"))
	resp, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Subject:    SubjectAttributes{DID: "did:web:test", BadgeJTI: "jti-1", IAL: "1", TrustLevel: "2"},
		Action:     ActionAttributes{Operation: "GET /v1/test"},
		Resource:   ResourceAttributes{Identifier: "/v1/test"},
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("decision = %q, want %q", resp.Decision, DecisionAllow)
	}
	if resp.DecisionID != "test-decision-001" {
		t.Errorf("decision_id = %q, want %q", resp.DecisionID, "test-decision-001")
	}
}

func TestHTTPPDPClient_PEPIDHeader(t *testing.T) {
	var gotPEPID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPEPID = r.Header.Get("X-Capiscio-PEP-ID")
		json.NewEncoder(w).Encode(DecisionResponse{Decision: DecisionAllow, DecisionID: "d1"})
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout, WithPEPID("my-pep-42"))
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if gotPEPID != "my-pep-42" {
		t.Errorf("X-Capiscio-PEP-ID = %q, want %q", gotPEPID, "my-pep-42")
	}
}

func TestHTTPPDPClient_InvalidDecision(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":    "ALLOW_OBSERVE", // not a valid PDP response
			"decision_id": "d1",
		})
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout)
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err == nil {
		t.Fatal("expected error for invalid decision, got nil")
	}
}

func TestHTTPPDPClient_EmptyDecisionID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":    "ALLOW",
			"decision_id": "",
		})
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout)
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err == nil {
		t.Fatal("expected error for empty decision_id, got nil")
	}
}

func TestHTTPPDPClient_4xxError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "bad request"}`))
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout)
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err == nil {
		t.Fatal("expected error for 400 status, got nil")
	}
}

func TestHTTPPDPClient_5xxError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout)
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err == nil {
		t.Fatal("expected error for 500 status, got nil")
	}
}

func TestHTTPPDPClient_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		json.NewEncoder(w).Encode(DecisionResponse{Decision: DecisionAllow, DecisionID: "d1"})
	}))
	defer server.Close()

	// 50ms timeout — server sleeps 200ms
	client := NewHTTPPDPClient(server.URL, 50*time.Millisecond)
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestHTTPPDPClient_MalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	client := NewHTTPPDPClient(server.URL, DefaultPDPTimeout)
	_, err := client.Evaluate(context.Background(), &DecisionRequest{
		PIPVersion: PIPVersion,
		Context:    ContextAttributes{TxnID: "txn-1", EnforcementMode: "EM-OBSERVE"},
	})
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

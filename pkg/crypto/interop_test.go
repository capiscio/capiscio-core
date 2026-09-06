package crypto

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
	jose "github.com/go-jose/go-jose/v4"
)

// This fixture was produced by an implementation independent of this package,
// following A2A specification section 8.4 directly: the payload is the card
// with `signatures` removed, canonicalized with RFC 8785, and the signature is
// ES256 over BASE64URL(protected) || "." || BASE64URL(payload).
//
// It deliberately carries the two constructs that this package used to get
// wrong, so a regression fails here rather than in production:
//
//   - `"streaming": false` and `"pushNotifications": false` are explicitly set,
//     and must survive canonicalization (spec 8.4.1)
//   - the description and url contain '<', '>' and '&', which RFC 8785 emits
//     literally and Go's encoding/json escapes
const interopSignedCard = `{
  "protocolVersion": "0.3.0",
  "name": "Interop Agent",
  "description": "planning <service> & routing",
  "url": "https://interop.example.com/a2a?tenant=a&mode=b",
  "version": "1.0.0",
  "capabilities": {"streaming": false, "pushNotifications": false},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [{"id": "plan", "name": "Plan", "description": "Plans routes", "tags": ["geo"]}],
  "signatures": [{
    "protected": "eyJhbGciOiJFUzI1NiIsImprdSI6Imh0dHBzOi8vaW50ZXJvcC5leGFtcGxlLmNvbS9qd2tzLmpzb24iLCJraWQiOiJpbnRlcm9wLWtleS0xIiwidHlwIjoiSk9TRSJ9",
    "signature": "AR32G971k9vIBf2d698nrsyOTFp2h_BVucwIoaQ26Eha0XuwpSKymPEXkjivxtad68rlGRlibU168bIMskwl4g"
  }]
}`

const interopJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"interop-key-1","x":"BMSUAJn4PU-IAvWhiqymE9p-cEmdh3GFI8hXdyODvTA","y":"xsJNHD_uNUrQ7knDtjmfO2THg_5NyaNjQ96Fkb5ORGo"}]}`

// The canonical payload the independent signer computed. Recording it makes a
// canonicalization regression report the actual difference rather than only a
// failed signature.
const interopCanonicalPayload = `{"capabilities":{"pushNotifications":false,"streaming":false},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"description":"planning <service> & routing","name":"Interop Agent","protocolVersion":"0.3.0","skills":[{"description":"Plans routes","id":"plan","name":"Plan","tags":["geo"]}],"url":"https://interop.example.com/a2a?tenant=a&mode=b","version":"1.0.0"}`

// stubJWKSFetcher serves a fixed key set, so the test exercises verification
// rather than network behaviour.
type stubJWKSFetcher struct {
	jwks string
}

func (s stubJWKSFetcher) Fetch(_ context.Context, _ string) (*jose.JSONWebKeySet, error) {
	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(s.jwks), &keySet); err != nil {
		return nil, err
	}
	return &keySet, nil
}

func TestCanonicalPayloadMatchesIndependentSigner(t *testing.T) {
	card := decodeCard(t, interopSignedCard)

	if got := canonical(t, card); got != interopCanonicalPayload {
		t.Errorf("canonical payload differs from the independent signer's\n got: %s\nwant: %s", got, interopCanonicalPayload)
	}
}

func TestVerifiesCardSignedByIndependentImplementation(t *testing.T) {
	var card agentcard.AgentCard
	if err := json.Unmarshal([]byte(interopSignedCard), &card); err != nil {
		t.Fatalf("failed to decode signed card: %v", err)
	}

	verifier := NewVerifierWithFetcher(stubJWKSFetcher{jwks: interopJWKS})

	result, err := verifier.VerifyAgentCardSignatures(context.Background(), &card)
	if err != nil {
		t.Fatalf("verification returned an error: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected the signature to verify, got errors: %v", result.Summary.Errors)
	}
}

// Tampering with the card must break verification. Without this, a test that
// only checks the happy path cannot distinguish a working verifier from one
// that accepts everything.
func TestRejectsTamperedCardFromIndependentImplementation(t *testing.T) {
	tampered := decodeTampered(t, interopSignedCard, "Interop Agent", "Evil Agent")

	verifier := NewVerifierWithFetcher(stubJWKSFetcher{jwks: interopJWKS})

	result, err := verifier.VerifyAgentCardSignatures(context.Background(), tampered)
	if err != nil {
		t.Fatalf("verification returned an error: %v", err)
	}

	if result.Valid {
		t.Error("a tampered card must not verify")
	}
}

func decodeTampered(t *testing.T, document, old, replacement string) *agentcard.AgentCard {
	t.Helper()
	modified := strings.Replace(document, old, replacement, 1)
	if modified == document {
		t.Fatalf("tampering did not change the document; %q not found", old)
	}
	var card agentcard.AgentCard
	if err := json.Unmarshal([]byte(modified), &card); err != nil {
		t.Fatalf("failed to decode tampered card: %v", err)
	}
	return &card
}

package crypto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
)

// decodeCard parses a card the way a verifier receives one, so the raw bytes
// are retained.
func decodeCard(t *testing.T, document string) *agentcard.AgentCard {
	t.Helper()
	var card agentcard.AgentCard
	if err := json.Unmarshal([]byte(document), &card); err != nil {
		t.Fatalf("failed to decode card: %v", err)
	}
	return &card
}

func canonical(t *testing.T, card *agentcard.AgentCard) string {
	t.Helper()
	out, err := CreateCanonicalJSON(card)
	if err != nil {
		t.Fatalf("CreateCanonicalJSON failed: %v", err)
	}
	return string(out)
}

// The worked example published in A2A specification section 8.4.1. If this
// fails, canonicalization is wrong and every signature check built on it is
// meaningless.
func TestCanonicalJSONMatchesSpecWorkedExample(t *testing.T) {
	card := decodeCard(t, `{
	  "name": "Example Agent",
	  "description": "",
	  "capabilities": {
	    "streaming": false,
	    "pushNotifications": false
	  },
	  "skills": []
	}`)

	const want = `{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}`

	if got := canonical(t, card); got != want {
		t.Errorf("canonical form does not match the specification's worked example\n got: %s\nwant: %s", got, want)
	}
}

// An `optional` field the sender explicitly set must survive canonicalization
// even when it holds a default (spec 8.4.1). Marshaling the struct dropped
// these, because AgentCapabilities uses plain bools with omitempty.
func TestExplicitlySetFalseSurvives(t *testing.T) {
	card := decodeCard(t, `{
	  "protocolVersion": "0.3.0",
	  "name": "Example Agent",
	  "description": "d",
	  "url": "https://example.com/a2a",
	  "version": "1.0.0",
	  "capabilities": {"streaming": false, "pushNotifications": false},
	  "defaultInputModes": ["text/plain"],
	  "defaultOutputModes": ["text/plain"],
	  "skills": []
	}`)

	got := canonical(t, card)

	for _, field := range []string{`"streaming":false`, `"pushNotifications":false`} {
		if !strings.Contains(got, field) {
			t.Errorf("expected %s to survive canonicalization, got: %s", field, got)
		}
	}
}

// A field the sender omitted must stay omitted. Struct fields without
// omitempty were emitted as zero values, adding content the signer never
// signed over.
func TestOmittedFieldsAreNotInvented(t *testing.T) {
	card := decodeCard(t, `{
	  "name": "Example Agent",
	  "description": "d",
	  "version": "1.0.0",
	  "capabilities": {},
	  "skills": []
	}`)

	got := canonical(t, card)

	for _, field := range []string{"protocolVersion", "url", "defaultInputModes", "defaultOutputModes"} {
		if strings.Contains(got, field) {
			t.Errorf("field %q was absent from the source document but appears in the canonical form: %s", field, got)
		}
	}
}

// RFC 8785 emits '<', '>' and '&' literally. Go's encoder escapes them, which
// changed the payload for any card carrying an ampersand in a query string.
func TestNoHTMLEscaping(t *testing.T) {
	card := decodeCard(t, `{
	  "name": "Example Agent",
	  "description": "planning <service> & routing",
	  "version": "1.0.0",
	  "capabilities": {},
	  "skills": [],
	  "url": "https://example.com/a2a?tenant=a&mode=b"
	}`)

	got := canonical(t, card)

	// Built from bytes so the source file carries no escape sequence of its own.
	unicodeEscape := string([]byte{'\\', 'u'})
	if strings.Contains(got, unicodeEscape) {
		t.Errorf("canonical form contains a unicode escape; RFC 8785 emits these characters literally: %s", got)
	}

	for _, literal := range []string{"?tenant=a&mode=b", "planning <service> & routing"} {
		if !strings.Contains(got, literal) {
			t.Errorf("expected %q to survive literally, got: %s", literal, got)
		}
	}
}

// The signatures field is excluded from the payload it signs over (spec 8.4.1).
func TestSignaturesAreExcluded(t *testing.T) {
	card := decodeCard(t, `{
	  "name": "Example Agent",
	  "description": "d",
	  "version": "1.0.0",
	  "capabilities": {},
	  "skills": [],
	  "signatures": [{"protected": "abc", "signature": "def"}]
	}`)

	if got := canonical(t, card); strings.Contains(got, "signatures") {
		t.Errorf("canonical form must not contain the signatures field: %s", got)
	}
}

// Key order in the received document must not affect the payload. This is the
// property canonicalization exists to provide.
func TestKeyOrderDoesNotChangeOutput(t *testing.T) {
	first := decodeCard(t, `{"name":"A","description":"d","version":"1.0.0","capabilities":{},"skills":[]}`)
	second := decodeCard(t, `{"skills":[],"capabilities":{},"version":"1.0.0","description":"d","name":"A"}`)

	if canonical(t, first) != canonical(t, second) {
		t.Errorf("key order changed the canonical form:\n%s\n%s", canonical(t, first), canonical(t, second))
	}
}

// Cards built in code carry no raw document, so the struct is the only source
// available. It must still canonicalize rather than error.
func TestProgrammaticCardFallsBackToStruct(t *testing.T) {
	card := &agentcard.AgentCard{
		Name:            "Test Agent",
		ProtocolVersion: "0.3.0",
		Version:         "1.0.0",
		Signatures:      []agentcard.Signature{{Protected: "abc", Signature: "def"}},
	}

	got := canonical(t, card)

	if strings.Contains(got, "signatures") {
		t.Errorf("signatures must be excluded: %s", got)
	}
	if !strings.Contains(got, `"name":"Test Agent"`) {
		t.Errorf("expected the card contents to survive: %s", got)
	}
}

// Nested objects are sorted recursively, and array order is preserved because
// arrays are ordered data, not a set.
func TestNestedObjectsAreCanonicalized(t *testing.T) {
	card := decodeCard(t, `{
	  "name": "A",
	  "description": "d",
	  "version": "1.0.0",
	  "capabilities": {},
	  "skills": [{"tags":["b","a"],"name":"S","id":"s","description":"x"}]
	}`)

	const wantSkill = `"skills":[{"description":"x","id":"s","name":"S","tags":["b","a"]}]`

	got := canonical(t, card)
	if !strings.Contains(got, wantSkill) {
		t.Errorf("nested object keys were not sorted, or array order was not preserved\n got: %s\nwant substring: %s", got, wantSkill)
	}
}

// A JSON `null` satisfies encoding/json when decoded into an AgentCard, and
// the retained document is then the four bytes "null". Canonicalizing that
// produced a signable payload for something that is not an agent card, so it
// must be refused instead.
func TestRejectsDocumentThatIsNotAnObject(t *testing.T) {
	card := decodeCard(t, `null`)

	if _, err := CreateCanonicalJSON(card); err == nil {
		t.Error("a document that is not a JSON object must not canonicalize")
	}
}

// RFC 8785 defines number formatting over IEEE 754 doubles. A literal outside
// that range has no canonical form, so canonicalization must fail rather than
// return a payload a signer and a verifier could disagree about.
func TestRejectsNumbersOutsideIEEE754Range(t *testing.T) {
	card := decodeCard(t, `{"name":"Example Agent","extensionNumber":1e400}`)

	if _, err := CreateCanonicalJSON(card); err == nil {
		t.Error("a number outside the IEEE 754 double range must not canonicalize")
	}
}

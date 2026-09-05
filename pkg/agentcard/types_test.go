package agentcard

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgentCard_JSONRoundTrip(t *testing.T) {
	// Create a fully populated AgentCard
	original := &AgentCard{
		ProtocolVersion: "0.3.0",
		Name:            "Test Agent",
		Description:     "A test agent",
		URL:             "https://example.com/agent",
		Version:         "1.0.0",
		Capabilities: AgentCapabilities{
			Streaming: true,
		},
		Signatures: []Signature{
			{Protected: "header", Signature: "sig"},
		},
	}

	// Marshal
	data, err := json.Marshal(original)
	assert.NoError(t, err)

	// Unmarshal
	var decoded AgentCard
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	// A decoded card also retains the bytes it came from, so it is not
	// struct-identical to one built in code. Compare the content instead.
	assert.Equal(t, *original, decoded.withoutRaw())
}

// A decoded card must keep its source document, because signature
// verification canonicalizes what actually arrived rather than the struct's
// rendering of it.
func TestAgentCard_RetainsSourceDocument(t *testing.T) {
	const document = `{"name":"Test Agent","capabilities":{"streaming":false}}`

	var decoded AgentCard
	assert.NoError(t, json.Unmarshal([]byte(document), &decoded))

	assert.Equal(t, document, string(decoded.Raw()),
		"the raw document must survive decoding byte for byte")
}

// A card built in code has no source document to retain.
func TestAgentCard_ProgrammaticCardHasNoRaw(t *testing.T) {
	card := &AgentCard{Name: "Test Agent"}

	assert.Nil(t, card.Raw())
}

// Mutating the caller's buffer after decoding must not change what the card
// retained, or a verifier could canonicalize something the signer never sent.
func TestAgentCard_RawIsCopied(t *testing.T) {
	document := []byte(`{"name":"Test Agent"}`)

	var decoded AgentCard
	assert.NoError(t, json.Unmarshal(document, &decoded))

	document[2] = 'X'

	assert.Equal(t, `{"name":"Test Agent"}`, string(decoded.Raw()))
}

// withoutRaw returns a copy with the retained document cleared, for tests that
// compare card content rather than provenance.
func (c AgentCard) withoutRaw() AgentCard {
	c.raw = nil
	return c
}

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

	// Compare
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Capabilities.Streaming, decoded.Capabilities.Streaming)
	assert.Equal(t, len(original.Signatures), len(decoded.Signatures))
	assert.Equal(t, original.Signatures[0].Protected, decoded.Signatures[0].Protected)
}

package did_test

import (
	"testing"

	"github.com/capiscio/capiscio-core/pkg/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDomain  string
		wantAgentID string
		wantPath    []string
		wantErr     error
	}{
		{
			name:        "valid agent DID",
			input:       "did:web:registry.capisc.io:agents:my-agent-001",
			wantDomain:  "registry.capisc.io",
			wantAgentID: "my-agent-001",
			wantPath:    []string{"agents", "my-agent-001"},
		},
		{
			name:        "valid agent DID with custom domain",
			input:       "did:web:example.com:agents:test-agent",
			wantDomain:  "example.com",
			wantAgentID: "test-agent",
			wantPath:    []string{"agents", "test-agent"},
		},
		{
			name:        "DID with no path (domain only)",
			input:       "did:web:example.com",
			wantDomain:  "example.com",
			wantAgentID: "",
			wantPath:    []string{},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: did.ErrInvalidDID,
		},
		{
			name:    "invalid prefix",
			input:   "did:key:abc123",
			wantErr: did.ErrUnsupportedMethod,
		},
		{
			name:    "too short",
			input:   "did:web",
			wantErr: did.ErrInvalidDID,
		},
		{
			name:    "not a DID",
			input:   "https://example.com",
			wantErr: did.ErrInvalidDID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, "web", parsed.Method)
			assert.Equal(t, tc.wantDomain, parsed.Domain)
			assert.Equal(t, tc.wantAgentID, parsed.AgentID)
			assert.Equal(t, tc.wantPath, parsed.PathSegments)
			assert.Equal(t, tc.input, parsed.Raw)
		})
	}
}

func TestDID_DocumentURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantURL string
	}{
		{
			name:    "agent DID",
			input:   "did:web:registry.capisc.io:agents:my-agent-001",
			wantURL: "https://registry.capisc.io/agents/my-agent-001/did.json",
		},
		{
			name:    "domain only",
			input:   "did:web:example.com",
			wantURL: "https://example.com/did.json",
		},
		{
			name:    "nested path",
			input:   "did:web:example.com:foo:bar:baz",
			wantURL: "https://example.com/foo/bar/baz/did.json",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.wantURL, parsed.DocumentURL())
		})
	}
}

func TestDID_String(t *testing.T) {
	input := "did:web:registry.capisc.io:agents:test-agent"
	parsed, err := did.Parse(input)
	require.NoError(t, err)
	assert.Equal(t, input, parsed.String())
}

func TestNewAgentDID(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		agentID  string
		expected string
	}{
		{
			name:     "standard domain",
			domain:   "registry.capisc.io",
			agentID:  "my-agent-001",
			expected: "did:web:registry.capisc.io:agents:my-agent-001",
		},
		{
			name:     "custom domain",
			domain:   "my-company.com",
			agentID:  "production-agent",
			expected: "did:web:my-company.com:agents:production-agent",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := did.NewAgentDID(tc.domain, tc.agentID)
			assert.Equal(t, tc.expected, result)

			// Verify it can be parsed back
			parsed, err := did.Parse(result)
			require.NoError(t, err)
			assert.Equal(t, tc.domain, parsed.Domain)
			assert.Equal(t, tc.agentID, parsed.AgentID)
		})
	}
}

func TestNewCapiscIOAgentDID(t *testing.T) {
	result := did.NewCapiscIOAgentDID("my-agent")
	assert.Equal(t, "did:web:registry.capisc.io:agents:my-agent", result)
}

func TestDID_IsAgentDID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid agent DID",
			input: "did:web:registry.capisc.io:agents:my-agent",
			want:  true,
		},
		{
			name:  "domain only",
			input: "did:web:example.com",
			want:  false,
		},
		{
			name:  "different path",
			input: "did:web:example.com:users:alice",
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := did.Parse(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.want, parsed.IsAgentDID())
		})
	}
}

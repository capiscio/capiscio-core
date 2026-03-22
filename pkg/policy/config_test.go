package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_MinimalValid(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
`
	cfg, err := Parse([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, "REG", cfg.MinTrustLevel)
}

func TestParse_FullConfig(t *testing.T) {
	yaml := `version: "1"
min_trust_level: DV
allowed_dids:
  - did:web:agent1.example.com
  - did:web:agent2.example.com
denied_dids:
  - did:web:evil.example.com
rate_limits:
  - did: did:web:agent1.example.com
    rpm: 100
operations:
  - pattern: "POST /tasks"
    min_trust_level: OV
    allowed_dids:
      - did:web:agent1.example.com
mcp_tools:
  - tool: file_read
    min_trust_level: EV
    denied_dids:
      - did:web:untrusted.example.com
`
	cfg, err := Parse([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "DV", cfg.MinTrustLevel)
	assert.Len(t, cfg.AllowedDIDs, 2)
	assert.Len(t, cfg.DeniedDIDs, 1)
	assert.Len(t, cfg.RateLimits, 1)
	assert.Equal(t, 100, cfg.RateLimits[0].RPM)
	assert.Len(t, cfg.Operations, 1)
	assert.Equal(t, "POST /tasks", cfg.Operations[0].Pattern)
	assert.Len(t, cfg.MCPTools, 1)
	assert.Equal(t, "file_read", cfg.MCPTools[0].Tool)
}

func TestParse_InvalidVersion(t *testing.T) {
	yaml := `version: "2.0"
min_trust_level: REG
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `version must be "1"`)
}

func TestParse_InvalidTrustLevel(t *testing.T) {
	yaml := `version: "1"
min_trust_level: PLATINUM
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid min_trust_level "PLATINUM"`)
}

func TestParse_InvalidDIDFormat(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
allowed_dids:
  - not-a-did
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid DID format "not-a-did"`)
}

func TestParse_DuplicateDIDs(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
allowed_dids:
  - did:web:agent.com
  - did:web:agent.com
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `duplicate DID "did:web:agent.com"`)
}

func TestParse_DIDInBothLists(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
allowed_dids:
  - did:web:agent.com
denied_dids:
  - did:web:agent.com
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicts with allowed_dids")
}

func TestParse_InvalidRateLimit(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
rate_limits:
  - did: did:web:agent.com
    rpm: 0
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpm must be positive")
}

func TestParse_EmptyOperationPattern(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
operations:
  - pattern: ""
    min_trust_level: DV
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern must not be empty")
}

func TestParse_EmptyMCPTool(t *testing.T) {
	yaml := `version: "1"
min_trust_level: REG
mcp_tools:
  - tool: ""
    min_trust_level: DV
`
	_, err := Parse([]byte(yaml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool must not be empty")
}

func TestParse_MalformedYAML(t *testing.T) {
	_, err := Parse([]byte("not: valid: yaml: ["))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse policy config")
}

func TestParse_EmptyTrustLevelAllowed(t *testing.T) {
	yaml := `version: "1"
min_trust_level: ""
`
	cfg, err := Parse([]byte(yaml))
	require.NoError(t, err)
	assert.Equal(t, "", cfg.MinTrustLevel)
}

func TestToMap_RoundTrip(t *testing.T) {
	cfg := &Config{
		MinTrustLevel: "DV",
		AllowedDIDs:   []string{"did:web:a.com"},
		DeniedDIDs:    []string{"did:web:b.com"},
		RateLimits:    []RateLimitRule{{DID: "did:web:a.com", RPM: 60}},
		Operations: []OperationRule{
			{
				Pattern:       "POST /tasks",
				MinTrustLevel: "OV",
				AllowedDIDs:   []string{"did:web:a.com"},
				DeniedDIDs:    []string{},
			},
		},
		MCPTools: []MCPToolRule{
			{
				Tool:          "file_read",
				MinTrustLevel: "EV",
				AllowedDIDs:   []string{},
				DeniedDIDs:    []string{"did:web:b.com"},
			},
		},
	}

	m := ToMap(cfg)
	assert.Equal(t, "DV", m["min_trust_level"])
	assert.Len(t, m["allowed_dids"], 1)
	assert.Len(t, m["denied_dids"], 1)
	assert.Len(t, m["rate_limits"], 1)
	assert.Len(t, m["operations"], 1)
	assert.Len(t, m["mcp_tools"], 1)
}

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := &Config{
		Version:       "99",
		MinTrustLevel: "INVALID",
		AllowedDIDs:   []string{"not-a-did"},
		RateLimits:    []RateLimitRule{{DID: "bad", RPM: -1}},
	}
	err := Validate(cfg)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, `version must be "1"`)
	assert.Contains(t, msg, `invalid min_trust_level`)
	assert.Contains(t, msg, `invalid DID format`)
	assert.Contains(t, msg, `rpm must be positive`)
}

func TestValidate_NilConfig(t *testing.T) {
	err := Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestValidate_DuplicateRateLimitDID(t *testing.T) {
	cfg := &Config{
		Version: "1",
		RateLimits: []RateLimitRule{
			{DID: "did:web:agent.example.com", RPM: 100},
			{DID: "did:web:agent.example.com", RPM: 50},
		},
	}
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate DID")
}

func TestValidate_OperationDIDValidation(t *testing.T) {
	cfg := &Config{
		Version: "1",
		Operations: []OperationRule{
			{
				Pattern:    "test.*",
				AllowedDIDs: []string{"not-a-did"},
			},
		},
	}
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operations[0].allowed_dids")
}

func TestValidate_MCPToolDIDValidation(t *testing.T) {
	cfg := &Config{
		Version: "1",
		MCPTools: []MCPToolRule{
			{
				Tool:       "my_tool",
				DeniedDIDs: []string{"invalid"},
			},
		},
	}
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mcp_tools[0].denied_dids")
}

func TestValidate_OperationDIDConflict(t *testing.T) {
	cfg := &Config{
		Version: "1",
		Operations: []OperationRule{
			{
				Pattern:    "agent.invoke",
				AllowedDIDs: []string{"did:web:a.example.com"},
				DeniedDIDs:  []string{"did:web:a.example.com"},
			},
		},
	}
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operations[0].denied_dids")
	assert.Contains(t, err.Error(), "conflicts with allowed")
}

func TestValidate_MCPToolDIDConflict(t *testing.T) {
	cfg := &Config{
		Version: "1",
		MCPTools: []MCPToolRule{
			{
				Tool:       "my_tool",
				AllowedDIDs: []string{"did:web:a.example.com"},
				DeniedDIDs:  []string{"did:web:a.example.com"},
			},
		},
	}
	err := Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mcp_tools[0].denied_dids")
	assert.Contains(t, err.Error(), "conflicts with allowed")
}

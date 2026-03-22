// Package policy provides shared policy configuration types and validation
// for the CapiscIO YAML policy config format. This is the canonical validator
// used by both the capiscio CLI and the capiscio-server.
package policy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the YAML schema for capiscio-policy.yaml.
// This defines the content of a policy document at any scope level
// (org, group, or agent).
type Config struct {
	Version       string          `yaml:"version" json:"version"`
	MinTrustLevel string          `yaml:"min_trust_level" json:"min_trust_level"`
	AllowedDIDs   []string        `yaml:"allowed_dids" json:"allowed_dids"`
	DeniedDIDs    []string        `yaml:"denied_dids" json:"denied_dids"`
	RateLimits    []RateLimitRule `yaml:"rate_limits" json:"rate_limits"`
	Operations    []OperationRule `yaml:"operations" json:"operations"`
	MCPTools      []MCPToolRule   `yaml:"mcp_tools" json:"mcp_tools"`
}

// RateLimitRule defines per-DID rate limiting.
type RateLimitRule struct {
	DID string `yaml:"did" json:"did"`
	RPM int    `yaml:"rpm" json:"rpm"`
}

// OperationRule defines operation-scoped trust/access rules.
type OperationRule struct {
	Pattern       string   `yaml:"pattern" json:"pattern"`
	MinTrustLevel string   `yaml:"min_trust_level" json:"min_trust_level"`
	AllowedDIDs   []string `yaml:"allowed_dids" json:"allowed_dids"`
	DeniedDIDs    []string `yaml:"denied_dids" json:"denied_dids"`
}

// MCPToolRule defines MCP tool-scoped trust/access rules.
type MCPToolRule struct {
	Tool          string   `yaml:"tool" json:"tool"`
	MinTrustLevel string   `yaml:"min_trust_level" json:"min_trust_level"`
	AllowedDIDs   []string `yaml:"allowed_dids" json:"allowed_dids"`
	DeniedDIDs    []string `yaml:"denied_dids" json:"denied_dids"`
}

// validTrustLevels defines the allowed trust level values.
var validTrustLevels = map[string]bool{
	"":    true, // empty means no trust requirement
	"SS":  true,
	"REG": true,
	"DV":  true,
	"OV":  true,
	"EV":  true,
}

// Parse parses and validates YAML policy config bytes.
// Returns an error if the YAML is malformed or fails validation.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy config: %w", err)
	}
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validateDIDList validates a list of DIDs for format and uniqueness.
// If crossCheck is non-nil, it also checks for DIDs appearing in both lists.
func validateDIDList(name string, dids []string, crossCheck map[string]bool) (seen map[string]bool, errs []string) {
	seen = make(map[string]bool)
	for _, did := range dids {
		if !strings.HasPrefix(did, "did:") {
			errs = append(errs, fmt.Sprintf("%s: invalid DID format %q", name, did))
		}
		if seen[did] {
			errs = append(errs, fmt.Sprintf("%s: duplicate DID %q", name, did))
		}
		seen[did] = true
		if crossCheck != nil && crossCheck[did] {
			errs = append(errs, fmt.Sprintf("%s: DID %q conflicts with allowed_dids", name, did))
		}
	}
	return
}

// Validate checks a parsed Config for semantic correctness.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("policy config is nil")
	}

	var errs []string

	if cfg.Version != "1" {
		errs = append(errs, fmt.Sprintf("version must be \"1\", got %q", cfg.Version))
	}

	if !validTrustLevels[cfg.MinTrustLevel] {
		errs = append(errs, fmt.Sprintf("invalid min_trust_level %q", cfg.MinTrustLevel))
	}

	allowedSeen, didErrs := validateDIDList("allowed_dids", cfg.AllowedDIDs, nil)
	errs = append(errs, didErrs...)

	_, didErrs = validateDIDList("denied_dids", cfg.DeniedDIDs, allowedSeen)
	errs = append(errs, didErrs...)

	// Validate rate limits
	rateSeen := make(map[string]bool)
	for i, rl := range cfg.RateLimits {
		if !strings.HasPrefix(rl.DID, "did:") {
			errs = append(errs, fmt.Sprintf("rate_limits[%d]: invalid DID format %q", i, rl.DID))
		}
		if rateSeen[rl.DID] {
			errs = append(errs, fmt.Sprintf("rate_limits[%d]: duplicate DID %q", i, rl.DID))
		}
		rateSeen[rl.DID] = true
		if rl.RPM <= 0 {
			errs = append(errs, fmt.Sprintf("rate_limits[%d]: rpm must be positive, got %d", i, rl.RPM))
		}
	}

	// Validate operations
	for i, op := range cfg.Operations {
		if op.Pattern == "" {
			errs = append(errs, fmt.Sprintf("operations[%d]: pattern must not be empty", i))
		}
		if !validTrustLevels[op.MinTrustLevel] {
			errs = append(errs, fmt.Sprintf("operations[%d]: invalid min_trust_level %q", i, op.MinTrustLevel))
		}
		opAllowedSeen, opDIDErrs := validateDIDList(fmt.Sprintf("operations[%d].allowed_dids", i), op.AllowedDIDs, nil)
		errs = append(errs, opDIDErrs...)
		_, opDeniedErrs := validateDIDList(fmt.Sprintf("operations[%d].denied_dids", i), op.DeniedDIDs, opAllowedSeen)
		errs = append(errs, opDeniedErrs...)
	}

	// Validate MCP tools
	for i, tool := range cfg.MCPTools {
		if tool.Tool == "" {
			errs = append(errs, fmt.Sprintf("mcp_tools[%d]: tool must not be empty", i))
		}
		if !validTrustLevels[tool.MinTrustLevel] {
			errs = append(errs, fmt.Sprintf("mcp_tools[%d]: invalid min_trust_level %q", i, tool.MinTrustLevel))
		}
		toolAllowedSeen, toolDIDErrs := validateDIDList(fmt.Sprintf("mcp_tools[%d].allowed_dids", i), tool.AllowedDIDs, nil)
		errs = append(errs, toolDIDErrs...)
		_, toolDeniedErrs := validateDIDList(fmt.Sprintf("mcp_tools[%d].denied_dids", i), tool.DeniedDIDs, toolAllowedSeen)
		errs = append(errs, toolDeniedErrs...)
	}

	if len(errs) > 0 {
		return fmt.Errorf("policy config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// ToMap converts a Config to the map format used in OPA data documents.
func ToMap(cfg *Config) map[string]interface{} {
	if cfg == nil {
		return nil
	}
	result := map[string]interface{}{
		"min_trust_level": cfg.MinTrustLevel,
	}

	allowed := make([]interface{}, len(cfg.AllowedDIDs))
	for i, d := range cfg.AllowedDIDs {
		allowed[i] = d
	}
	result["allowed_dids"] = allowed

	denied := make([]interface{}, len(cfg.DeniedDIDs))
	for i, d := range cfg.DeniedDIDs {
		denied[i] = d
	}
	result["denied_dids"] = denied

	rates := make([]interface{}, len(cfg.RateLimits))
	for i, rl := range cfg.RateLimits {
		rates[i] = map[string]interface{}{
			"did": rl.DID,
			"rpm": rl.RPM,
		}
	}
	result["rate_limits"] = rates

	ops := make([]interface{}, len(cfg.Operations))
	for i, op := range cfg.Operations {
		entry := map[string]interface{}{
			"pattern":         op.Pattern,
			"min_trust_level": op.MinTrustLevel,
		}
		opAllowed := make([]interface{}, len(op.AllowedDIDs))
		for j, d := range op.AllowedDIDs {
			opAllowed[j] = d
		}
		entry["allowed_dids"] = opAllowed
		opDenied := make([]interface{}, len(op.DeniedDIDs))
		for j, d := range op.DeniedDIDs {
			opDenied[j] = d
		}
		entry["denied_dids"] = opDenied
		ops[i] = entry
	}
	result["operations"] = ops

	tools := make([]interface{}, len(cfg.MCPTools))
	for i, t := range cfg.MCPTools {
		entry := map[string]interface{}{
			"tool":            t.Tool,
			"min_trust_level": t.MinTrustLevel,
		}
		tAllowed := make([]interface{}, len(t.AllowedDIDs))
		for j, d := range t.AllowedDIDs {
			tAllowed[j] = d
		}
		entry["allowed_dids"] = tAllowed
		tDenied := make([]interface{}, len(t.DeniedDIDs))
		for j, d := range t.DeniedDIDs {
			tDenied[j] = d
		}
		entry["denied_dids"] = tDenied
		tools[i] = entry
	}
	result["mcp_tools"] = tools

	return result
}

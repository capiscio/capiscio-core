// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"fmt"
	"strings"
)

// ToolRequest represents a request to invoke a tool.
type ToolRequest struct {
	// ToolName is the name of the tool being invoked.
	// For MCP tools: "mcp:<server>/<tool>"
	// For function calls: "function:<name>"
	ToolName string

	// Arguments are the tool invocation arguments.
	// Type depends on the tool specification.
	Arguments map[string]any

	// Description is a human-readable description of the invocation.
	Description string
}

// Domain implements Request.
func (r *ToolRequest) Domain() string {
	return "tool"
}

// Capability implements Request.
func (r *ToolRequest) Capability() string {
	return r.ToolName
}

// ToolHookConfig configures the tool mediation hook.
type ToolHookConfig struct {
	// Logger for mediation operations.
	Logger Logger

	// Emitter for RFC-011 events.
	Emitter EventEmitter

	// DefaultDeny rejects requests when no explicit grant is found.
	// Default: false (allow if authenticated with valid badge)
	DefaultDeny bool

	// RequireEnvelope requires an authority envelope for tool access.
	// When true, badge-only requests are denied.
	// Default: false
	RequireEnvelope bool

	// MinTrustLevel is the minimum badge trust level required.
	// Requests with lower trust levels are denied.
	// Default: 0 (any level accepted)
	MinTrustLevel int

	// AllowedTools is a list of tools that are always allowed.
	// Supports wildcards: "mcp:*" matches all MCP tools.
	// If empty, all tools are subject to capability checking.
	AllowedTools []string

	// DeniedTools is a list of tools that are always denied.
	// Takes precedence over AllowedTools and capability grants.
	DeniedTools []string
}

// ToolHook mediates tool invocation requests.
//
// Evaluation order:
//  1. Check DeniedTools list (always deny if matched)
//  2. Check AllowedTools list (always allow if matched)
//  3. Check envelope capabilities (if envelope present)
//  4. Apply default policy (deny or allow based on DefaultDeny)
type ToolHook struct {
	config ToolHookConfig
	logger Logger
	emitter EventEmitter
}

// NewToolHook creates a tool mediation hook.
func NewToolHook(config ToolHookConfig) *ToolHook {
	h := &ToolHook{
		config:  config,
		logger:  config.Logger,
		emitter: config.Emitter,
	}
	if h.logger == nil {
		h.logger = noopLogger{}
	}
	if h.emitter == nil {
		h.emitter = noopEmitter{}
	}
	return h
}

// Mediate evaluates a tool invocation request.
func (h *ToolHook) Mediate(ctx context.Context, mctx *Context, request Request) (*Result, error) {
	toolReq, ok := request.(*ToolRequest)
	if !ok {
		return nil, fmt.Errorf("ToolHook requires *ToolRequest, got %T", request)
	}

	h.logger.Debug("mediating tool request",
		"tool", toolReq.ToolName,
		"subject", mctx.SubjectDID,
		"trust_level", mctx.TrustLevel,
	)

	// 0. Check trust material availability
	if !mctx.HasTrustMaterial() {
		h.logger.Warn("no trust material available for mediation")
		result := DenyResult("builtin:no_trust_material", "trust material not available")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 1. Check authentication
	if !mctx.HasBadge() {
		result := DenyResult("builtin:unauthenticated", "no valid badge presented")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 2. Check trust level
	if mctx.TrustLevel < h.config.MinTrustLevel {
		result := DenyResult("builtin:insufficient_trust_level",
			fmt.Sprintf("trust level %d < required %d", mctx.TrustLevel, h.config.MinTrustLevel))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 3. Check RequireEnvelope
	if h.config.RequireEnvelope && !mctx.HasEnvelope() {
		result := DenyResult("builtin:envelope_required", "authority envelope required for tool access")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 4. Check DeniedTools (always deny if matched)
	if h.matchesPatterns(toolReq.ToolName, h.config.DeniedTools) {
		result := DenyResult("builtin:denied_tool_list",
			fmt.Sprintf("tool %q is on the denied list", toolReq.ToolName))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 5. Check AllowedTools (always allow if matched)
	if h.matchesPatterns(toolReq.ToolName, h.config.AllowedTools) {
		result := AllowResult("builtin:allowed_tool_list",
			fmt.Sprintf("tool %q is on the allowed list", toolReq.ToolName))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 6. Check envelope capabilities
	if mctx.HasEnvelope() {
		if mctx.CapabilitySatisfied("tool:" + toolReq.ToolName) ||
			mctx.CapabilitySatisfied("tool:*") {
			result := AllowResult("envelope:capability_grant",
				fmt.Sprintf("capability granted for tool %q", toolReq.ToolName))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}

		// Envelope present but no matching capability
		if h.config.DefaultDeny {
			result := DenyResult("envelope:no_capability",
				fmt.Sprintf("no capability grant for tool %q", toolReq.ToolName))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 7. Apply default policy
	if h.config.DefaultDeny {
		result := DenyResult("builtin:default_deny",
			fmt.Sprintf("no explicit grant for tool %q", toolReq.ToolName))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// Default allow with valid badge
	result := AllowResult("builtin:badge_authenticated",
		fmt.Sprintf("authenticated caller may invoke tool %q", toolReq.ToolName))
	h.emitter.EmitDecision(mctx, result, request)
	return result, nil
}

// matchesPatterns checks if a tool name matches any pattern in the list.
// Supports wildcards: "mcp:*" matches "mcp:github/search", etc.
func (h *ToolHook) matchesPatterns(toolName string, patterns []string) bool {
	for _, pattern := range patterns {
		if h.matchPattern(toolName, pattern) {
			return true
		}
	}
	return false
}

// matchPattern checks if a tool name matches a single pattern.
func (h *ToolHook) matchPattern(toolName, pattern string) bool {
	// Exact match
	if toolName == pattern {
		return true
	}

	// Wildcard suffix match (e.g., "mcp:*" matches "mcp:github/search")
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(toolName, prefix) {
			return true
		}
	}

	return false
}

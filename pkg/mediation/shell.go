// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"fmt"
	"strings"
)

// ShellRequest represents a request to execute a shell command.
type ShellRequest struct {
	// Command is the command being executed.
	Command string

	// Args are the command arguments.
	Args []string

	// WorkingDirectory is the directory where the command will run.
	WorkingDirectory string

	// Description is a human-readable description of the execution.
	Description string
}

// Domain implements Request.
func (r *ShellRequest) Domain() string {
	return "shell"
}

// Capability implements Request.
func (r *ShellRequest) Capability() string {
	return fmt.Sprintf("shell:%s", r.Command)
}

// FullCommand returns the full command with arguments.
func (r *ShellRequest) FullCommand() string {
	if len(r.Args) == 0 {
		return r.Command
	}
	return r.Command + " " + strings.Join(r.Args, " ")
}

// ShellHookConfig configures the shell mediation hook.
type ShellHookConfig struct {
	// Logger for mediation operations.
	Logger Logger

	// Emitter for RFC-011 events.
	Emitter EventEmitter

	// AllowedCommands is a list of commands that are always allowed.
	// Supports prefixes: "git *" matches all git commands.
	AllowedCommands []string

	// DeniedCommands is a list of commands that are always denied.
	// Takes precedence over AllowedCommands.
	DeniedCommands []string

	// DangerousPatterns is a list of patterns that indicate dangerous commands.
	// These are always denied. Includes common dangerous patterns by default.
	DangerousPatterns []string

	// DefaultDeny rejects requests when no explicit grant is found.
	// Default: true (safest for shell execution)
	DefaultDeny bool

	// RequireEnvelope requires an authority envelope for shell access.
	// Default: true (shell access is highly sensitive)
	RequireEnvelope bool

	// MinTrustLevel is the minimum badge trust level required.
	// Default: 2 (requires verified identity)
	MinTrustLevel int
}

// defaultDangerousPatterns are always denied regardless of configuration.
var defaultDangerousPatterns = []string{
	// Data destruction
	"rm -rf /",
	"rm -rf ~",
	"rm -rf /*",
	"rm -rf .",
	"mkfs",
	"dd if=",
	":(){:|:&};:", // Fork bomb

	// Privilege escalation
	"sudo ",
	"su ",
	"chmod 777",
	"chown root",

	// Remote access / reverse shell
	"nc -e",
	"bash -i",
	"python -c 'import socket'",
	"curl | sh",
	"curl | bash",
	"wget | sh",
	"wget | bash",

	// Credential access
	"cat /etc/shadow",
	"cat /etc/passwd",
	"cat ~/.ssh/id_",
	"cat ~/.aws/credentials",

	// System modification
	"systemctl stop",
	"service stop",
	"iptables -F",
	"ufw disable",
}

// safeCommands are commonly safe commands that may be allowed with lower trust.
var safeCommands = []string{
	"ls", "pwd", "echo", "cat", "head", "tail", "grep",
	"find", "wc", "sort", "uniq", "date", "whoami",
}

// ShellHook mediates shell execution requests.
type ShellHook struct {
	config  ShellHookConfig
	logger  Logger
	emitter EventEmitter
}

// NewShellHook creates a shell mediation hook.
func NewShellHook(config ShellHookConfig) *ShellHook {
	h := &ShellHook{
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

// Mediate evaluates a shell execution request.
func (h *ShellHook) Mediate(ctx context.Context, mctx *Context, request Request) (*Result, error) {
	shellReq, ok := request.(*ShellRequest)
	if !ok {
		return nil, fmt.Errorf("ShellHook requires *ShellRequest, got %T", request)
	}

	fullCmd := shellReq.FullCommand()

	h.logger.Debug("mediating shell request",
		"command", shellReq.Command,
		"full_command", fullCmd,
		"subject", mctx.SubjectDID,
	)

	// 0. Check trust material availability
	if !mctx.HasTrustMaterial() {
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
			fmt.Sprintf("trust level %d < required %d for shell access", mctx.TrustLevel, h.config.MinTrustLevel))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 3. Check RequireEnvelope
	if h.config.RequireEnvelope && !mctx.HasEnvelope() {
		result := DenyResult("builtin:envelope_required", "authority envelope required for shell access")
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// 4. Check default dangerous patterns (always enforced)
	for _, pattern := range defaultDangerousPatterns {
		if h.containsPattern(fullCmd, pattern) {
			result := DenyResult("builtin:dangerous_pattern",
				fmt.Sprintf("command matches dangerous pattern %q", pattern))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 5. Check configured dangerous patterns
	for _, pattern := range h.config.DangerousPatterns {
		if h.containsPattern(fullCmd, pattern) {
			result := DenyResult("config:dangerous_pattern",
				fmt.Sprintf("command matches configured dangerous pattern %q", pattern))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 6. Check DeniedCommands
	for _, denied := range h.config.DeniedCommands {
		if h.matchCommand(shellReq.Command, fullCmd, denied) {
			result := DenyResult("config:denied_command",
				fmt.Sprintf("command %q is denied by configuration", shellReq.Command))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 7. Check AllowedCommands
	for _, allowed := range h.config.AllowedCommands {
		if h.matchCommand(shellReq.Command, fullCmd, allowed) {
			result := AllowResult("config:allowed_command",
				fmt.Sprintf("command %q is allowed by configuration", shellReq.Command))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 8. Check envelope capabilities
	if mctx.HasEnvelope() {
		if mctx.CapabilitySatisfied("shell.*") || mctx.CapabilitySatisfied("shell.execute") {
			result := AllowResult("envelope:capability_grant",
				fmt.Sprintf("capability granted for shell command %q", shellReq.Command))
			h.emitter.EmitDecision(mctx, result, request)
			return result, nil
		}
	}

	// 9. Apply default policy (shell defaults to deny)
	if h.config.DefaultDeny {
		result := DenyResult("builtin:default_deny",
			fmt.Sprintf("no explicit grant for shell command %q", shellReq.Command))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// Default allow (only if DefaultDeny = false AND command passes all checks)
	result := AllowResult("builtin:default_allow",
		fmt.Sprintf("authenticated caller may execute %q", shellReq.Command))
	h.emitter.EmitDecision(mctx, result, request)
	return result, nil
}

// containsPattern checks if the command contains a dangerous pattern.
func (h *ShellHook) containsPattern(fullCmd, pattern string) bool {
	return strings.Contains(strings.ToLower(fullCmd), strings.ToLower(pattern))
}

// matchCommand checks if a command matches a pattern.
func (h *ShellHook) matchCommand(cmd, fullCmd, pattern string) bool {
	// Exact command match
	if cmd == pattern {
		return true
	}

	// Wildcard suffix (e.g., "git *" matches "git" with any args)
	if strings.HasSuffix(pattern, " *") {
		prefix := strings.TrimSuffix(pattern, " *")
		if cmd == prefix || strings.HasPrefix(fullCmd, prefix+" ") {
			return true
		}
	}

	// Prefix match (e.g., "git" matches "git-status")
	if strings.HasPrefix(cmd, pattern) {
		return true
	}

	return false
}

// IsSafeCommand checks if a command is in the safe commands list.
func IsSafeCommand(cmd string) bool {
	for _, safe := range safeCommands {
		if cmd == safe {
			return true
		}
	}
	return false
}

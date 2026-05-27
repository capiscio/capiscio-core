// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
)

// Hook evaluates capability requests against locally cached trust material.
//
// Implementations MUST adhere to RFC-001 §2.3 (Verification Locality):
//   - MUST NOT make synchronous network calls during Mediate()
//   - MUST operate against locally cached trust material only
//   - MUST emit RFC-011 events for all decisions
//
// The Hook interface is domain-agnostic. Specialized implementations exist
// for different capability domains (tools, filesystem, network, shell).
type Hook interface {
	// Mediate evaluates whether the request should be allowed, denied, or delegated.
	//
	// Parameters:
	//   - ctx: Go context for cancellation and deadlines (NOT for trust material)
	//   - mctx: Mediation context with trust material and verified artifacts
	//   - request: Domain-specific request (ToolRequest, FileRequest, etc.)
	//
	// Returns:
	//   - Result: The enforcement decision with audit trail
	//   - error: Non-nil only for internal errors (not policy denials)
	//
	// Implementations MUST be safe for concurrent use.
	Mediate(ctx context.Context, mctx *Context, request Request) (*Result, error)
}

// Request is the interface for mediation requests.
// Specialized request types implement this interface.
type Request interface {
	// Domain returns the capability domain (e.g., "tool", "file", "network", "shell").
	Domain() string

	// Capability returns the specific capability being requested.
	// Format is domain-specific.
	Capability() string
}

// Logger is the interface for mediation logging.
// Compatible with slog.Logger.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// noopLogger is a no-op logger for when no logger is provided.
type noopLogger struct{}

func (noopLogger) Debug(msg string, args ...any) {}
func (noopLogger) Info(msg string, args ...any)  {}
func (noopLogger) Warn(msg string, args ...any)  {}
func (noopLogger) Error(msg string, args ...any) {}

// EventEmitter emits RFC-011 runtime events.
// Events are emitted asynchronously and MUST NOT block mediation.
type EventEmitter interface {
	// EmitDecision emits an enforcement decision event.
	EmitDecision(mctx *Context, result *Result, request Request)

	// EmitCapabilityCheck emits a capability check event.
	EmitCapabilityCheck(mctx *Context, capability string, granted bool)
}

// noopEmitter is a no-op event emitter for when no emitter is provided.
type noopEmitter struct{}

func (noopEmitter) EmitDecision(mctx *Context, result *Result, request Request)    {}
func (noopEmitter) EmitCapabilityCheck(mctx *Context, capability string, granted bool) {}

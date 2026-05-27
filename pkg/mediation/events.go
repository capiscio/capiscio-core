// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

// Package mediation provides RFC-011 runtime event types and emission.
//
// Events model authority transitions — the moments when trust decisions are made,
// authority changes hands, and enforcement actions occur. They are NOT telemetry;
// they are first-class runtime artifacts supporting audit, compliance, and provenance.
//
// Per RFC-011 §4.2, event emission is a local operation that MUST NOT block on
// network I/O. Events are buffered locally and forwarded asynchronously.
package mediation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EventType is a dot-delimited identifier categorizing the event.
// Event types follow the taxonomy defined in RFC-011 §5.
type EventType string

// Identity events (RFC-011 §5.1)
const (
	EventIdentityVerified EventType = "identity.verified"
	EventIdentityInvalid  EventType = "identity.invalid"
	EventIdentityExpired  EventType = "identity.expired"
	EventIdentityRevoked  EventType = "identity.revoked"
)

// Authority events (RFC-011 §5.2)
const (
	EventAuthorityRequested EventType = "authority.requested"
	EventAuthorityGranted   EventType = "authority.granted"
	EventAuthorityDenied    EventType = "authority.denied"
	EventAuthorityNarrowed  EventType = "authority.narrowed"
	EventAuthorityDelegated EventType = "authority.delegated"
	EventAuthorityExpired   EventType = "authority.expired"
)

// Runtime events (RFC-011 §5.3)
const (
	EventRuntimeAttached    EventType = "runtime.attached"
	EventRuntimeDetached    EventType = "runtime.detached"
	EventExecutionStarted   EventType = "execution.started"
	EventExecutionCompleted EventType = "execution.completed"
	EventExecutionAborted   EventType = "execution.aborted"
)

// Tool events (RFC-011 §5.4)
const (
	EventToolRequested EventType = "tool.requested"
	EventToolPermitted EventType = "tool.permitted"
	EventToolDenied    EventType = "tool.denied"
	EventToolExecuted  EventType = "tool.executed"
)

// Resource events (RFC-011 §5.5)
const (
	EventResourceNetworkRequested   EventType = "resource.network.requested"
	EventResourceNetworkPermitted   EventType = "resource.network.permitted"
	EventResourceNetworkDenied      EventType = "resource.network.denied"
	EventResourceFilesystemRequested EventType = "resource.filesystem.requested"
	EventResourceFilesystemPermitted EventType = "resource.filesystem.permitted"
	EventResourceFilesystemDenied    EventType = "resource.filesystem.denied"
	EventResourceShellRequested     EventType = "resource.shell.requested"
	EventResourceShellPermitted     EventType = "resource.shell.permitted"
	EventResourceShellDenied        EventType = "resource.shell.denied"
)

// Trust events (RFC-011 §5.6)
const (
	EventTrustSignatureCreated  EventType = "trust.signature.created"
	EventTrustSignatureVerified EventType = "trust.signature.verified"
	EventTrustSignatureInvalid  EventType = "trust.signature.invalid"
	EventTrustAttestationGenerated EventType = "trust.attestation.generated"
	EventTrustRevocationChecked EventType = "trust.revocation.checked"
)

// ComponentType identifies the type of emitting component.
type ComponentType string

const (
	ComponentSDK     ComponentType = "sdk"
	ComponentSidecar ComponentType = "sidecar"
	ComponentGateway ComponentType = "gateway"
	ComponentPEP     ComponentType = "pep"
)

// Event is the RFC-011 event envelope.
//
// Per RFC-011 §6.1, this structure contains all metadata required for
// audit, compliance, and provenance reconstruction.
type Event struct {
	// SchemaVersion is the event schema version. MUST be "1.0" per RFC-011.
	SchemaVersion string `json:"schema_version"`

	// EventID is a unique event identifier (UUID v4 prefixed with "evt_").
	EventID string `json:"event_id"`

	// EventType categorizes the event per RFC-011 §5 taxonomy.
	EventType EventType `json:"event_type"`

	// Timestamp is ISO 8601 with millisecond precision.
	Timestamp string `json:"timestamp"`

	// Emitter identifies the component that generated the event.
	Emitter EmitterInfo `json:"emitter"`

	// Context carries correlation identifiers for distributed tracing.
	Context EventContext `json:"context,omitempty"`

	// Payload contains event-specific data per RFC-011 §5 tables.
	Payload map[string]any `json:"payload"`

	// Signature is an optional JWS compact signature for integrity.
	Signature string `json:"signature,omitempty"`
}

// EmitterInfo identifies the component emitting the event.
type EmitterInfo struct {
	// ComponentID is the identifier of the emitting component.
	ComponentID string `json:"component_id"`

	// ComponentType is one of: sdk, sidecar, gateway, pep.
	ComponentType ComponentType `json:"component_type"`

	// Version is the version of the emitting component.
	Version string `json:"version,omitempty"`
}

// EventContext carries correlation identifiers for distributed tracing.
type EventContext struct {
	// TraceID links events to the same originator workflow (RFC-001 §3.2).
	TraceID string `json:"trace_id,omitempty"`

	// TxnID links events to the same transaction (RFC-004).
	TxnID string `json:"txn_id,omitempty"`

	// HopID links events to the same hop in a delegation chain (RFC-004).
	HopID string `json:"hop_id,omitempty"`
}

// NewEvent creates a new event with a fresh UUID and timestamp.
func NewEvent(eventType EventType, emitter EmitterInfo) *Event {
	return &Event{
		SchemaVersion: "1.0",
		EventID:       "evt_" + uuid.New().String(),
		EventType:     eventType,
		Timestamp:     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Emitter:       emitter,
		Payload:       make(map[string]any),
	}
}

// WithContext adds correlation context to the event.
func (e *Event) WithContext(traceID, txnID, hopID string) *Event {
	e.Context = EventContext{
		TraceID: traceID,
		TxnID:   txnID,
		HopID:   hopID,
	}
	return e
}

// WithPayload adds a key-value pair to the payload.
func (e *Event) WithPayload(key string, value any) *Event {
	e.Payload[key] = value
	return e
}

// IdentityPayload contains fields for identity events (RFC-011 §5.1).
type IdentityPayload struct {
	BadgeJTI   string `json:"badge_jti,omitempty"`
	SubjectDID string `json:"subject_did,omitempty"`
	TrustLevel int    `json:"trust_level,omitempty"`
	IAL        int    `json:"ial,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	ExpiredAt  string `json:"expired_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

// AuthorityPayload contains fields for authority events (RFC-011 §5.2).
type AuthorityPayload struct {
	SubjectDID            string   `json:"subject_did,omitempty"`
	RequestedCapabilities []string `json:"requested_capabilities,omitempty"`
	EffectiveCapabilities []string `json:"effective_capabilities,omitempty"`
	EnvelopeHash          string   `json:"envelope_hash,omitempty"`
	PolicyVersion         string   `json:"policy_version,omitempty"`
	Reason                string   `json:"reason,omitempty"`
	ParentEnvelopeHash    string   `json:"parent_envelope_hash,omitempty"`
	ChildEnvelopeHash     string   `json:"child_envelope_hash,omitempty"`
	NarrowedCapabilities  []string `json:"narrowed_capabilities,omitempty"`
	IssuerDID             string   `json:"issuer_did,omitempty"`
	DelegationDepth       int      `json:"delegation_depth,omitempty"`
	ExpiredAt             string   `json:"expired_at,omitempty"`
}

// RuntimePayload contains fields for runtime events (RFC-011 §5.3).
type RuntimePayload struct {
	ComponentID     string `json:"component_id,omitempty"`
	AttachedAt      string `json:"attached_at,omitempty"`
	DetachedAt      string `json:"detached_at,omitempty"`
	EnforcementMode string `json:"enforcement_mode,omitempty"`
	Reason          string `json:"reason,omitempty"`
	TxnID           string `json:"txn_id,omitempty"`
	HopID           string `json:"hop_id,omitempty"`
	SubjectDID      string `json:"subject_did,omitempty"`
	EnvelopeHash    string `json:"envelope_hash,omitempty"`
	Outcome         string `json:"outcome,omitempty"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
}

// ToolPayload contains fields for tool events (RFC-011 §5.4).
type ToolPayload struct {
	ToolName     string `json:"tool_name,omitempty"`
	ServerDID    string `json:"server_did,omitempty"`
	SubjectDID   string `json:"subject_did,omitempty"`
	EnvelopeHash string `json:"envelope_hash,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	DurationMs   int64  `json:"duration_ms,omitempty"`
}

// ResourcePayload contains fields for resource events (RFC-011 §5.5).
//
// Per RFC-011 §5.5, resource payloads MUST use canonicalized representations,
// NOT raw values. Raw URLs, paths, and commands can contain secrets.
type ResourcePayload struct {
	// Network fields
	Scheme             string `json:"scheme,omitempty"`
	TargetHost         string `json:"target_host,omitempty"`
	TargetPort         int    `json:"target_port,omitempty"`
	PathClassification string `json:"path_classification,omitempty"`
	Method             string `json:"method,omitempty"`

	// Filesystem fields
	PathHash  string `json:"path_hash,omitempty"`
	Operation string `json:"operation,omitempty"`

	// Shell fields
	CommandHash           string `json:"command_hash,omitempty"`
	CommandClassification string `json:"command_classification,omitempty"`

	// Common fields
	SubjectDID string `json:"subject_did,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// TrustPayload contains fields for trust events (RFC-011 §5.6).
type TrustPayload struct {
	ArtifactType    string `json:"artifact_type,omitempty"`
	ArtifactHash    string `json:"artifact_hash,omitempty"`
	SignerDID       string `json:"signer_did,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	HopID           string `json:"hop_id,omitempty"`
	AttesterDID     string `json:"attester_did,omitempty"`
	AttestationHash string `json:"attestation_hash,omitempty"`
	JTI             string `json:"jti,omitempty"`
	Revoked         bool   `json:"revoked,omitempty"`
	CacheAgeSeconds int    `json:"cache_age_seconds,omitempty"`
}

// HashForEvent computes a SHA-256 hash of a value for event payloads.
// Used to canonicalize sensitive values like paths and commands per RFC-011 §5.5.
func HashForEvent(value string) string {
	h := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(h[:])
}

// ClassifyPath converts a filesystem path to a classification pattern.
// Example: "/home/user/documents/file.txt" → "/home/*/documents/*"
func ClassifyPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	// Replace middle components with wildcards, preserve structure
	classified := make([]string, len(parts))
	for i, part := range parts {
		if i == 0 || i == 1 || i == len(parts)-1 {
			// Keep root, first dir, and last component
			if i == len(parts)-1 && strings.Contains(part, ".") {
				classified[i] = "*" + part[strings.LastIndex(part, "."):]
			} else {
				classified[i] = part
			}
		} else {
			classified[i] = "*"
		}
	}
	return strings.Join(classified, "/")
}

// ClassifyCommand extracts the command classification from a shell command.
// Example: "git commit -m 'message'" → "git"
func ClassifyCommand(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return "unknown"
	}
	// Extract basename of command
	cmdPath := parts[0]
	if idx := strings.LastIndex(cmdPath, "/"); idx >= 0 {
		cmdPath = cmdPath[idx+1:]
	}
	return cmdPath
}

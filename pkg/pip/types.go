package pip

import "encoding/json"

// PIPVersion is the protocol version identifier.
// PEPs MUST include this in every request.
// PEPs MUST reject responses from PDPs that do not recognize the version.
const PIPVersion = "capiscio.pip.v1"

// DecisionAllow and DecisionDeny are the only valid PDP response values.
// ALLOW_OBSERVE is a PEP telemetry value (§7.4), NOT a PDP response.
const (
	DecisionAllow   = "ALLOW"
	DecisionDeny    = "DENY"
	DecisionObserve = "ALLOW_OBSERVE" // PEP-only: emitted when EM-OBSERVE falls back on PDP unavailability
)

// DecisionRequest is the canonical PDP query (RFC-005 §5.1).
type DecisionRequest struct {
	PIPVersion  string             `json:"pip_version"`
	Subject     SubjectAttributes  `json:"subject"`
	Action      ActionAttributes   `json:"action"`
	Resource    ResourceAttributes `json:"resource"`
	Context     ContextAttributes  `json:"context"`
	Environment EnvironmentAttrs   `json:"environment"`
}

// SubjectAttributes identifies the acting agent.
type SubjectAttributes struct {
	DID        string `json:"did"`         // Badge sub (Claims.Subject)
	BadgeJTI   string `json:"badge_jti"`   // Badge jti (Claims.JTI)
	IAL        string `json:"ial"`         // Badge ial (Claims.IAL)
	TrustLevel string `json:"trust_level"` // Badge vc.credentialSubject.level (Claims.TrustLevel())
}

// ActionAttributes identify what is being attempted.
type ActionAttributes struct {
	CapabilityClass *string `json:"capability_class"` // null in badge-only mode
	Operation       string  `json:"operation"`        // tool name, HTTP method+route, etc.
}

// ResourceAttributes identify the target.
type ResourceAttributes struct {
	Identifier string `json:"identifier"` // target resource URI
}

// ContextAttributes provide correlation and authority context.
type ContextAttributes struct {
	TxnID             string          `json:"txn_id"`
	HopID             *string         `json:"hop_id"`             // OPTIONAL
	EnvelopeID        *string         `json:"envelope_id"`        // null in badge-only
	DelegationDepth   *int            `json:"delegation_depth"`   // null in badge-only
	Constraints       json.RawMessage `json:"constraints"`        // null in badge-only; see §3.1.9
	ParentConstraints json.RawMessage `json:"parent_constraints"` // null in badge-only; see §3.1.9
	EnforcementMode   string          `json:"enforcement_mode"`   // PEP-level config
}

// EnvironmentAttrs provide PEP context.
type EnvironmentAttrs struct {
	Workspace *string `json:"workspace,omitempty"` // OPTIONAL
	PEPID     *string `json:"pep_id,omitempty"`    // OPTIONAL
	Time      *string `json:"time,omitempty"`       // RECOMMENDED, ISO 8601
}

// DecisionResponse is the canonical PDP response (RFC-005 §6.1).
type DecisionResponse struct {
	Decision    string       `json:"decision"`              // "ALLOW" or "DENY"
	DecisionID  string       `json:"decision_id"`           // globally unique
	Obligations []Obligation `json:"obligations"`           // may be empty
	Reason      string       `json:"reason,omitempty"`      // human-readable
	TTL         *int         `json:"ttl,omitempty"`          // cache lifetime seconds
}

// Obligation is a conditional contract per RFC-005 §7.1.
type Obligation struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params"` // opaque JSON — PEP passes to handler without interpretation
}

// ValidDecision returns true if d is a valid PDP response decision value.
func ValidDecision(d string) bool {
	return d == DecisionAllow || d == DecisionDeny
}

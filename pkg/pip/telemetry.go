package pip

// Policy telemetry field constants (RFC-005 §10).
// These MUST be emitted on every policy enforcement event.
const (
	// TelemetryDecisionID is REQUIRED on every policy enforcement event.
	TelemetryDecisionID = "capiscio.policy.decision_id"

	// TelemetryDecision is REQUIRED on every policy enforcement event.
	// Values: "ALLOW", "DENY", or "ALLOW_OBSERVE"
	TelemetryDecision = "capiscio.policy.decision"

	// TelemetryOverride indicates break-glass was used.
	TelemetryOverride = "capiscio.policy.override"

	// TelemetryOverrideJTI is the break-glass token JTI.
	TelemetryOverrideJTI = "capiscio.policy.override_jti"

	// TelemetryErrorCode is REQUIRED when PDP is unavailable.
	TelemetryErrorCode = "capiscio.policy.error_code"

	// PolicyEventName is the RECOMMENDED event name.
	PolicyEventName = "capiscio.policy_enforced"

	// ErrorCodePDPUnavailable indicates PDP could not be reached.
	ErrorCodePDPUnavailable = "PDP_UNAVAILABLE"

	// TelemetryBundleStale is emitted when the embedded PDP's policy bundle
	// exceeds the staleness threshold (RFC-005 Appendix B §B.4).
	TelemetryBundleStale = "capiscio.policy.bundle_stale"

	// ErrorCodeBundleStale indicates the policy bundle is stale.
	// Distinct from PDP_UNAVAILABLE: the PDP evaluated successfully,
	// but the underlying data may be out of date.
	ErrorCodeBundleStale = "BUNDLE_STALE"
)

// TxnIDHeader is the HTTP header for transaction ID propagation (RFC-004).
const TxnIDHeader = "X-Capiscio-Txn"

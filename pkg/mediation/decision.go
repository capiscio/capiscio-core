// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import "time"

// Decision represents the outcome of a mediation evaluation.
type Decision string

const (
	// DecisionAllow permits the requested capability.
	DecisionAllow Decision = "allow"

	// DecisionDeny rejects the requested capability.
	DecisionDeny Decision = "deny"

	// DecisionDelegate indicates the request should be forwarded to another
	// agent in the delegation chain. The DelegateTarget field specifies
	// the target agent's DID.
	DecisionDelegate Decision = "delegate"
)

// Result contains the outcome of a mediation evaluation.
type Result struct {
	// Decision is the enforcement outcome.
	Decision Decision

	// Reason provides a human-readable explanation for the decision.
	// For denials, this should explain what capability was missing.
	Reason string

	// PolicyRef identifies the policy rule that produced this decision.
	// Format: "policy:<policy_id>:<rule_id>" or "builtin:<rule_name>"
	PolicyRef string

	// DelegateTarget is the DID of the agent to delegate to.
	// Only set when Decision == DecisionDelegate.
	DelegateTarget string

	// Obligations are post-decision requirements that the caller must fulfill.
	// Example: "audit:log_full_request", "notify:owner@example.com"
	Obligations []string

	// Metadata contains additional context about the decision.
	Metadata map[string]string

	// Timestamp is when the decision was made.
	Timestamp time.Time

	// TxnID is the transaction identifier for tracing.
	TxnID string

	// HopID identifies this specific hop in a delegation chain.
	HopID string
}

// IsAllowed returns true if the decision permits the capability.
func (r *Result) IsAllowed() bool {
	return r.Decision == DecisionAllow
}

// IsDenied returns true if the decision rejects the capability.
func (r *Result) IsDenied() bool {
	return r.Decision == DecisionDeny
}

// IsDelegate returns true if the decision indicates delegation.
func (r *Result) IsDelegate() bool {
	return r.Decision == DecisionDelegate
}

// WithObligation adds an obligation to the result.
func (r *Result) WithObligation(obligation string) *Result {
	r.Obligations = append(r.Obligations, obligation)
	return r
}

// WithMetadata adds a metadata entry to the result.
func (r *Result) WithMetadata(key, value string) *Result {
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
	}
	r.Metadata[key] = value
	return r
}

// AllowResult creates an allow decision.
func AllowResult(policyRef, reason string) *Result {
	return &Result{
		Decision:  DecisionAllow,
		Reason:    reason,
		PolicyRef: policyRef,
		Timestamp: time.Now(),
	}
}

// DenyResult creates a deny decision.
func DenyResult(policyRef, reason string) *Result {
	return &Result{
		Decision:  DecisionDeny,
		Reason:    reason,
		PolicyRef: policyRef,
		Timestamp: time.Now(),
	}
}

// DelegateResult creates a delegate decision.
func DelegateResult(policyRef, target, reason string) *Result {
	return &Result{
		Decision:       DecisionDelegate,
		Reason:         reason,
		PolicyRef:      policyRef,
		DelegateTarget: target,
		Timestamp:      time.Now(),
	}
}

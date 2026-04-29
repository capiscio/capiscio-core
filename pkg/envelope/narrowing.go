package envelope

import "fmt"

// ValidateNarrowing checks all PEP-enforceable monotonic narrowing dimensions
// between a parent and child envelope per RFC-008 §8.
//
// This validates:
//   - Capability class (§8.2): child must equal or narrow parent
//   - Temporal bounds (§8.3): child must not exceed parent's temporal window
//   - Delegation depth (§8.4): child must strictly decrement depth
//   - DID chain (§6.3): child issuer must be parent subject
//
// Constraint subset validation (§8.5) is NOT checked here — that is the PDP's
// responsibility per the RFC.
func ValidateNarrowing(parent, child *Payload) error {
	// §6.3: DID chain continuity
	if child.IssuerDID != parent.SubjectDID {
		return NewError(ErrCodeChainBroken,
			fmt.Sprintf("child issuer_did %q does not match parent subject_did %q",
				child.IssuerDID, parent.SubjectDID))
	}

	// §8.2: Capability class — child must be same or more specific
	if !IsWithinScope(child.CapabilityClass, parent.CapabilityClass) {
		return NewError(ErrCodeNarrowingViolation,
			fmt.Sprintf("capability class %q is not within scope of parent %q",
				child.CapabilityClass, parent.CapabilityClass))
	}

	// §8.3: Temporal bounds — child must not exceed parent's window
	if child.ExpiresAt > parent.ExpiresAt {
		return NewError(ErrCodeNarrowingViolation,
			fmt.Sprintf("child expires_at %d exceeds parent expires_at %d",
				child.ExpiresAt, parent.ExpiresAt))
	}
	if child.IssuedAt < parent.IssuedAt {
		return NewError(ErrCodeNarrowingViolation,
			fmt.Sprintf("child issued_at %d precedes parent issued_at %d",
				child.IssuedAt, parent.IssuedAt))
	}

	// §8.4: Delegation depth — must be strictly decremented
	if child.DelegationDepthRemaining >= parent.DelegationDepthRemaining {
		return NewError(ErrCodeNarrowingViolation,
			fmt.Sprintf("child depth %d is not less than parent depth %d",
				child.DelegationDepthRemaining, parent.DelegationDepthRemaining))
	}

	return nil
}

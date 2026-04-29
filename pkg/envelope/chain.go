package envelope

import (
	"crypto"
	"fmt"
)

// Chain is an ordered list of envelope tokens [E₀, E₁, ..., Eₙ].
// E₀ is the root (parent_authority_hash == nil).
type Chain []*Token

// DeriveEnvelope creates a derived (child) envelope from a parent envelope.
// It computes the parent_authority_hash, validates narrowing, and signs.
// privateKey must be ed25519.PrivateKey belonging to the parent's subject.
// keyID is the DID key reference for the JWS kid header.
func DeriveEnvelope(parent *Token, childPayload *Payload, privateKey crypto.PrivateKey, keyID string) (string, error) {
	if parent == nil {
		return "", fmt.Errorf("parent token is required")
	}
	if childPayload == nil {
		return "", fmt.Errorf("child payload is required")
	}

	// Set parent authority hash
	hash := ComputeHash(parent.Raw)
	childPayload.ParentAuthorityHash = &hash

	// Check that parent allows further delegation
	if parent.Payload.DelegationDepthRemaining <= 0 {
		return "", NewError(ErrCodeDepthExceeded,
			"parent envelope has no remaining delegation depth")
	}

	// Validate narrowing before signing
	if err := ValidateNarrowing(parent.Payload, childPayload); err != nil {
		return "", fmt.Errorf("narrowing validation failed: %w", err)
	}

	return SignEnvelope(childPayload, privateKey, keyID)
}

// ValidateChainIntegrity checks the structural integrity of a delegation chain.
// This validates hash links, DID continuity, narrowing rules, and TxnID consistency.
// It does NOT verify signatures or badges — use Verifier.VerifyChain for full verification.
func ValidateChainIntegrity(chain Chain) error {
	if len(chain) == 0 {
		return NewError(ErrCodeMalformed, "chain is empty")
	}

	// First element must be a root envelope
	root := chain[0]
	if !root.Payload.IsRoot() {
		return NewError(ErrCodeChainBroken, "first envelope in chain must be a root (parent_authority_hash == nil)")
	}

	txnID := root.Payload.TxnID

	for i := 1; i < len(chain); i++ {
		prev := chain[i-1]
		curr := chain[i]

		// TxnID consistency
		if curr.Payload.TxnID != txnID {
			return NewError(ErrCodeChainBroken,
				fmt.Sprintf("envelope %d has txn_id %q, expected %q", i, curr.Payload.TxnID, txnID))
		}

		// Hash link: curr.parent_authority_hash must equal SHA-256(prev.Raw)
		expectedHash := ComputeHash(prev.Raw)
		if curr.Payload.ParentAuthorityHash == nil {
			return NewError(ErrCodeChainBroken,
				fmt.Sprintf("envelope %d has nil parent_authority_hash (expected %s)", i, expectedHash))
		}
		if *curr.Payload.ParentAuthorityHash != expectedHash {
			return NewError(ErrCodeChainBroken,
				fmt.Sprintf("envelope %d has parent_authority_hash %q, expected %q",
					i, *curr.Payload.ParentAuthorityHash, expectedHash))
		}

		// Monotonic narrowing (includes DID chain check)
		if err := ValidateNarrowing(prev.Payload, curr.Payload); err != nil {
			return WrapError(ErrCodeChainBroken,
				fmt.Sprintf("narrowing violation at chain position %d", i), err)
		}
	}

	return nil
}

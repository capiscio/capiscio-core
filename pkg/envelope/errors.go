package envelope

import (
	"errors"
	"fmt"
)

// Error codes for Authority Envelope operations per RFC-008.
const (
	// ErrCodeMalformed indicates the JWS structure or payload is invalid.
	ErrCodeMalformed = "ENVELOPE_MALFORMED"

	// ErrCodeSignatureInvalid indicates JWS signature verification failed.
	ErrCodeSignatureInvalid = "ENVELOPE_SIGNATURE_INVALID"

	// ErrCodeExpired indicates the envelope has expired (now >= expires_at).
	ErrCodeExpired = "ENVELOPE_EXPIRED"

	// ErrCodeNotYetValid indicates issued_at is in the future.
	ErrCodeNotYetValid = "ENVELOPE_NOT_YET_VALID"

	// ErrCodeAlgorithmForbidden indicates a forbidden algorithm (none, HMAC).
	ErrCodeAlgorithmForbidden = "ENVELOPE_ALGORITHM_FORBIDDEN"

	// ErrCodeBadgeBindingFailed indicates issuer/subject badge JTI mismatch.
	ErrCodeBadgeBindingFailed = "ENVELOPE_BADGE_BINDING_FAILED"

	// ErrCodeChainBroken indicates a chain integrity failure (hash or DID mismatch).
	ErrCodeChainBroken = "ENVELOPE_CHAIN_BROKEN"

	// ErrCodeNarrowingViolation indicates monotonic narrowing was violated.
	ErrCodeNarrowingViolation = "ENVELOPE_NARROWING_VIOLATION"

	// ErrCodeDepthExceeded indicates an attempt to delegate at depth 0.
	ErrCodeDepthExceeded = "ENVELOPE_DEPTH_EXCEEDED"

	// ErrCodeChainTooDeep indicates the chain exceeds the PEP's configured
	// maximum chain length (RFC-008 §15.1.1).
	ErrCodeChainTooDeep = "ENVELOPE_CHAIN_TOO_DEEP"

	// ErrCodeKeyNotBound indicates the signing key is not bound to the issuer DID.
	ErrCodeKeyNotBound = "ENVELOPE_KEY_NOT_BOUND"

	// ErrCodeCapabilityInvalid indicates an invalid capability class format.
	ErrCodeCapabilityInvalid = "ENVELOPE_CAPABILITY_INVALID"

	// ErrCodePayloadTooLarge indicates the envelope payload exceeds the maximum size.
	ErrCodePayloadTooLarge = "ENVELOPE_PAYLOAD_TOO_LARGE"

	// ErrCodeScopeInsufficient indicates the PDP determined the envelope's
	// capability_class does not cover the requested operation (RFC-008 §9.3).
	ErrCodeScopeInsufficient = "ENVELOPE_SCOPE_INSUFFICIENT"
)

// Error represents an envelope operation error with an RFC-008 error code.
type Error struct {
	// Code is one of the ENVELOPE_* error codes.
	Code string

	// Message is a human-readable description.
	Message string

	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for errors.Is/errors.As.
func (e *Error) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches a target error code.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return e.Code == t.Code
	}
	return false
}

// NewError creates a new Error with the given code and message.
func NewError(code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// WrapError creates a new Error that wraps an underlying error.
func WrapError(code, message string, cause error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// ScopeInsufficientRejection is the structured rejection payload returned when
// a PEP denies a request due to ENVELOPE_SCOPE_INSUFFICIENT (RFC-008 §9.3.1).
//
// The payload intentionally omits any hint about what capability_class would
// have been sufficient — policy information MUST NOT leak through the error surface.
type ScopeInsufficientRejection struct {
	// Error is always ErrCodeScopeInsufficient.
	Error string `json:"error"`

	// RequestedCapability is the capability class the agent attempted to invoke.
	RequestedCapability string `json:"requested_capability"`

	// PresentedCapability is the capability_class from the envelope that was evaluated.
	PresentedCapability string `json:"presented_capability"`

	// EnvelopeID is the envelope_id of the insufficient envelope.
	EnvelopeID string `json:"envelope_id"`

	// TxnID is the transaction correlation ID.
	TxnID string `json:"txn_id"`
}

// NewScopeInsufficientRejection creates a structured rejection payload per RFC-008 §9.3.1.
func NewScopeInsufficientRejection(requestedCap, presentedCap, envelopeID, txnID string) *ScopeInsufficientRejection {
	return &ScopeInsufficientRejection{
		Error:               ErrCodeScopeInsufficient,
		RequestedCapability: requestedCap,
		PresentedCapability: presentedCap,
		EnvelopeID:          envelopeID,
		TxnID:               txnID,
	}
}

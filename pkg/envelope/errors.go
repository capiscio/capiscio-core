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

	// ErrCodeKeyNotBound indicates the signing key is not bound to the issuer DID.
	ErrCodeKeyNotBound = "ENVELOPE_KEY_NOT_BOUND"

	// ErrCodeCapabilityInvalid indicates an invalid capability class format.
	ErrCodeCapabilityInvalid = "ENVELOPE_CAPABILITY_INVALID"

	// ErrCodePayloadTooLarge indicates the envelope payload exceeds the maximum size.
	ErrCodePayloadTooLarge = "ENVELOPE_PAYLOAD_TOO_LARGE"
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

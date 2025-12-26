package badge

import (
	"errors"
	"fmt"
)

// Error codes as defined in RFC-002 §8.4.
// These are spec-level error codes, not HTTP status codes.
const (
	// ErrCodeMalformed indicates the JWS structure is invalid.
	ErrCodeMalformed = "BADGE_MALFORMED"

	// ErrCodeSignatureInvalid indicates signature verification failed.
	ErrCodeSignatureInvalid = "BADGE_SIGNATURE_INVALID"

	// ErrCodeExpired indicates current time >= exp.
	ErrCodeExpired = "BADGE_EXPIRED"

	// ErrCodeNotYetValid indicates current time < iat.
	ErrCodeNotYetValid = "BADGE_NOT_YET_VALID"

	// ErrCodeIssuerUntrusted indicates iss is not in the trusted issuer list.
	ErrCodeIssuerUntrusted = "BADGE_ISSUER_UNTRUSTED"

	// ErrCodeAudienceMismatch indicates the verifier is not in the aud claim.
	ErrCodeAudienceMismatch = "BADGE_AUDIENCE_MISMATCH"

	// ErrCodeRevoked indicates the badge jti is on the revocation list.
	ErrCodeRevoked = "BADGE_REVOKED"

	// ErrCodeClaimsInvalid indicates required claims are missing or malformed.
	ErrCodeClaimsInvalid = "BADGE_CLAIMS_INVALID"

	// ErrCodeAgentDisabled indicates the agent sub is disabled.
	ErrCodeAgentDisabled = "BADGE_AGENT_DISABLED"

	// ErrCodeRevocationCheckFailed indicates revocation check failed.
	// RFC-002 v1.3 §7.5: Used when sync fails AND cache stale for levels 2+.
	ErrCodeRevocationCheckFailed = "REVOCATION_CHECK_FAILED"
)

// Error represents a badge verification error with an RFC-002 error code.
type Error struct {
	// Code is one of the BADGE_* error codes.
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

// Predefined sentinel errors for common cases.
// Use these with errors.Is() for type-safe error checking.
var (
	// ErrMalformed is returned when the JWS structure is invalid.
	ErrMalformed = NewError(ErrCodeMalformed, "badge structure is invalid")

	// ErrSignatureInvalid is returned when signature verification fails.
	ErrSignatureInvalid = NewError(ErrCodeSignatureInvalid, "signature verification failed")

	// ErrExpired is returned when the badge has expired.
	ErrExpired = NewError(ErrCodeExpired, "badge has expired")

	// ErrNotYetValid is returned when the badge is not yet valid (iat in future).
	ErrNotYetValid = NewError(ErrCodeNotYetValid, "badge is not yet valid")

	// ErrIssuerUntrusted is returned when the issuer is not trusted.
	ErrIssuerUntrusted = NewError(ErrCodeIssuerUntrusted, "issuer is not trusted")

	// ErrAudienceMismatch is returned when verifier is not in audience.
	ErrAudienceMismatch = NewError(ErrCodeAudienceMismatch, "verifier not in badge audience")

	// ErrRevoked is returned when the badge has been revoked.
	ErrRevoked = NewError(ErrCodeRevoked, "badge has been revoked")

	// ErrClaimsInvalid is returned when required claims are missing or malformed.
	ErrClaimsInvalid = NewError(ErrCodeClaimsInvalid, "required claims missing or malformed")

	// ErrAgentDisabled is returned when the agent has been disabled.
	ErrAgentDisabled = NewError(ErrCodeAgentDisabled, "agent has been disabled")

	// ErrRevocationCheckFailed is returned when revocation check fails with stale cache.
	// RFC-002 v1.3 §7.5: Used for fail-closed on stale cache for levels 2+.
	ErrRevocationCheckFailed = NewError(ErrCodeRevocationCheckFailed, "revocation check failed")
)

// AsError checks if err is an Error and returns it if so.
func AsError(err error) (*Error, bool) {
	var badgeErr *Error
	if errors.As(err, &badgeErr) {
		return badgeErr, true
	}
	return nil, false
}

// GetErrorCode extracts the error code from an Error, or returns empty string.
func GetErrorCode(err error) string {
	if badgeErr, ok := AsError(err); ok {
		return badgeErr.Code
	}
	return ""
}

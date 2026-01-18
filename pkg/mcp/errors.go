package mcp

import "errors"

// Error codes for MCP operations
var (
	// ErrBadgeMissing indicates a badge was required but not provided
	ErrBadgeMissing = errors.New("badge required but not provided")

	// ErrBadgeInvalid indicates the badge is malformed or unverifiable
	ErrBadgeInvalid = errors.New("badge is invalid or malformed")

	// ErrBadgeExpired indicates the badge has expired
	ErrBadgeExpired = errors.New("badge has expired")

	// ErrBadgeRevoked indicates the badge has been revoked
	ErrBadgeRevoked = errors.New("badge has been revoked")

	// ErrTrustInsufficient indicates the trust level is below minimum required
	ErrTrustInsufficient = errors.New("trust level insufficient")

	// ErrToolNotAllowed indicates the tool is not in the allowed list
	ErrToolNotAllowed = errors.New("tool not allowed")

	// ErrIssuerUntrusted indicates the badge issuer is not trusted
	ErrIssuerUntrusted = errors.New("badge issuer not trusted")

	// ErrPolicyDenied indicates policy evaluation failed
	ErrPolicyDenied = errors.New("policy denied access")

	// ErrDIDInvalid indicates the DID is malformed
	ErrDIDInvalid = errors.New("DID is invalid")

	// ErrDIDMismatch indicates the badge subject doesn't match disclosed DID
	ErrDIDMismatch = errors.New("badge subject does not match disclosed DID")

	// ErrOriginMismatch indicates the transport origin doesn't match did:web host
	ErrOriginMismatch = errors.New("transport origin does not match DID host")

	// ErrPathMismatch indicates the endpoint path doesn't match did:web path
	ErrPathMismatch = errors.New("endpoint path does not match DID path")

	// ErrAPIKeyInvalid indicates the API key is invalid
	ErrAPIKeyInvalid = errors.New("API key is invalid")
)

// DenyReason represents the reason for access denial (RFC-006 §6.4)
type DenyReason int

const (
	DenyReasonUnspecified DenyReason = iota
	DenyReasonBadgeMissing
	DenyReasonBadgeInvalid
	DenyReasonBadgeExpired
	DenyReasonBadgeRevoked
	DenyReasonTrustInsufficient
	DenyReasonToolNotAllowed
	DenyReasonIssuerUntrusted
	DenyReasonPolicyDenied
)

// String returns the RFC-006 §10 compliant error code string
func (r DenyReason) String() string {
	switch r {
	case DenyReasonBadgeMissing:
		return "TOOL_AUTH_MISSING"
	case DenyReasonBadgeInvalid:
		return "TOOL_BADGE_INVALID"
	case DenyReasonBadgeExpired:
		return "TOOL_BADGE_INVALID"
	case DenyReasonBadgeRevoked:
		return "TOOL_BADGE_REVOKED"
	case DenyReasonTrustInsufficient:
		return "TOOL_TRUST_INSUFFICIENT"
	case DenyReasonToolNotAllowed:
		return "TOOL_NOT_FOUND"
	case DenyReasonIssuerUntrusted:
		return "TOOL_ISSUER_UNTRUSTED"
	case DenyReasonPolicyDenied:
		return "TOOL_POLICY_DENIED"
	default:
		return "UNSPECIFIED"
	}
}

// ErrorToDenyReason converts an error to a DenyReason
func ErrorToDenyReason(err error) DenyReason {
	switch {
	case errors.Is(err, ErrBadgeMissing):
		return DenyReasonBadgeMissing
	case errors.Is(err, ErrBadgeInvalid):
		return DenyReasonBadgeInvalid
	case errors.Is(err, ErrBadgeExpired):
		return DenyReasonBadgeExpired
	case errors.Is(err, ErrBadgeRevoked):
		return DenyReasonBadgeRevoked
	case errors.Is(err, ErrTrustInsufficient):
		return DenyReasonTrustInsufficient
	case errors.Is(err, ErrToolNotAllowed):
		return DenyReasonToolNotAllowed
	case errors.Is(err, ErrIssuerUntrusted):
		return DenyReasonIssuerUntrusted
	case errors.Is(err, ErrPolicyDenied):
		return DenyReasonPolicyDenied
	default:
		return DenyReasonUnspecified
	}
}

// ServerErrorCode represents server verification error codes (RFC-007 §8)
// These codes align with RFC-006 error conventions for consistency.
type ServerErrorCode int

const (
	ServerErrorNone ServerErrorCode = iota
	// SERVER_IDENTITY_MISSING - No server identity disclosed (UNVERIFIED_ORIGIN)
	ServerErrorCodeDIDMissing
	// SERVER_BADGE_MISSING - DID disclosed but no badge (DECLARED_PRINCIPAL)
	ServerErrorCodeBadgeMissing
	// SERVER_BADGE_INVALID - Badge signature or expiry verification failed
	ServerErrorCodeBadgeInvalid
	// SERVER_BADGE_REVOKED - Server badge has been revoked
	ServerErrorCodeBadgeRevoked
	// SERVER_TRUST_INSUFFICIENT - Trust level below required min_trust_level
	ServerErrorCodeTrustInsufficient
	// SERVER_DID_MISMATCH - Badge subject does not match disclosed DID
	ServerErrorCodeDIDMismatch
	// SERVER_ISSUER_UNTRUSTED - Badge issuer not in trusted_issuers
	ServerErrorCodeIssuerUntrusted
	// SERVER_DOMAIN_MISMATCH - did:web host does not match transport origin
	ServerErrorCodeOriginMismatch
	// SERVER_PATH_MISMATCH - did:web path does not match MCP endpoint path
	ServerErrorCodePathMismatch
	// SERVER_DID_RESOLUTION_FAILED - Could not resolve DID document
	ServerErrorCodeDIDResolutionFailed
	// SERVER_POP_FAILED - Proof of Possession verification failed
	ServerErrorCodePoPFailed
	// SERVER_POP_EXPIRED - PoP challenge expired
	ServerErrorCodePoPExpired
	// SERVER_KEY_FETCH_FAILED - Could not fetch server public key
	ServerErrorCodeKeyFetchFailed
)

// String returns the string representation of the server error code
// These match the RFC-007 §8 error code names
func (c ServerErrorCode) String() string {
	switch c {
	case ServerErrorCodeDIDMissing:
		return "SERVER_IDENTITY_MISSING"
	case ServerErrorCodeBadgeMissing:
		return "SERVER_BADGE_MISSING"
	case ServerErrorCodeBadgeInvalid:
		return "SERVER_BADGE_INVALID"
	case ServerErrorCodeBadgeRevoked:
		return "SERVER_BADGE_REVOKED"
	case ServerErrorCodeTrustInsufficient:
		return "SERVER_TRUST_INSUFFICIENT"
	case ServerErrorCodeDIDMismatch:
		return "SERVER_DID_MISMATCH"
	case ServerErrorCodeIssuerUntrusted:
		return "SERVER_ISSUER_UNTRUSTED"
	case ServerErrorCodeOriginMismatch:
		return "SERVER_DOMAIN_MISMATCH"
	case ServerErrorCodePathMismatch:
		return "SERVER_PATH_MISMATCH"
	case ServerErrorCodeDIDResolutionFailed:
		return "SERVER_DID_RESOLUTION_FAILED"
	case ServerErrorCodePoPFailed:
		return "SERVER_POP_FAILED"
	case ServerErrorCodePoPExpired:
		return "SERVER_POP_EXPIRED"
	case ServerErrorCodeKeyFetchFailed:
		return "SERVER_KEY_FETCH_FAILED"
	default:
		return "NONE"
	}
}

// ErrorToServerErrorCode converts an error to a ServerErrorCode
func ErrorToServerErrorCode(err error) ServerErrorCode {
	switch {
	case errors.Is(err, ErrDIDInvalid):
		return ServerErrorCodeDIDResolutionFailed
	case errors.Is(err, ErrBadgeInvalid):
		return ServerErrorCodeBadgeInvalid
	case errors.Is(err, ErrBadgeExpired):
		return ServerErrorCodeBadgeInvalid
	case errors.Is(err, ErrBadgeRevoked):
		return ServerErrorCodeBadgeRevoked
	case errors.Is(err, ErrTrustInsufficient):
		return ServerErrorCodeTrustInsufficient
	case errors.Is(err, ErrDIDMismatch):
		return ServerErrorCodeDIDMismatch
	case errors.Is(err, ErrOriginMismatch):
		return ServerErrorCodeOriginMismatch
	case errors.Is(err, ErrPathMismatch):
		return ServerErrorCodePathMismatch
	case errors.Is(err, ErrIssuerUntrusted):
		return ServerErrorCodeIssuerUntrusted
	case errors.Is(err, ErrBadgeMissing):
		return ServerErrorCodeBadgeMissing
	default:
		return ServerErrorNone
	}
}

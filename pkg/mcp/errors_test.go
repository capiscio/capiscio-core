package mcp

import (
	"testing"
)

func TestDenyReasonString(t *testing.T) {
	// RFC-006 §10 compliant TOOL_* error codes
	tests := []struct {
		reason   DenyReason
		expected string
	}{
		{DenyReasonUnspecified, "UNSPECIFIED"},
		{DenyReasonBadgeMissing, "TOOL_AUTH_MISSING"},
		{DenyReasonBadgeInvalid, "TOOL_BADGE_INVALID"},
		{DenyReasonBadgeExpired, "TOOL_BADGE_INVALID"},
		{DenyReasonBadgeRevoked, "TOOL_BADGE_REVOKED"},
		{DenyReasonTrustInsufficient, "TOOL_TRUST_INSUFFICIENT"},
		{DenyReasonToolNotAllowed, "TOOL_NOT_FOUND"},
		{DenyReasonIssuerUntrusted, "TOOL_ISSUER_UNTRUSTED"},
		{DenyReasonPolicyDenied, "TOOL_POLICY_DENIED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.reason.String(); got != tt.expected {
				t.Errorf("DenyReason.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrorToDenyReason(t *testing.T) {
	tests := []struct {
		err      error
		expected DenyReason
	}{
		{ErrBadgeMissing, DenyReasonBadgeMissing},
		{ErrBadgeInvalid, DenyReasonBadgeInvalid},
		{ErrBadgeExpired, DenyReasonBadgeExpired},
		{ErrBadgeRevoked, DenyReasonBadgeRevoked},
		{ErrTrustInsufficient, DenyReasonTrustInsufficient},
		{ErrToolNotAllowed, DenyReasonToolNotAllowed},
		{ErrIssuerUntrusted, DenyReasonIssuerUntrusted},
		{ErrPolicyDenied, DenyReasonPolicyDenied},
		{nil, DenyReasonUnspecified},
	}

	for _, tt := range tests {
		name := "nil"
		if tt.err != nil {
			name = tt.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			if got := ErrorToDenyReason(tt.err); got != tt.expected {
				t.Errorf("ErrorToDenyReason() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestServerErrorCodeString(t *testing.T) {
	// Tests use RFC-007 §8 compliant error code names
	tests := []struct {
		code     ServerErrorCode
		expected string
	}{
		{ServerErrorNone, "NONE"},
		{ServerErrorCodeDIDMissing, "SERVER_IDENTITY_MISSING"},
		{ServerErrorCodeBadgeMissing, "SERVER_BADGE_MISSING"},
		{ServerErrorCodeBadgeInvalid, "SERVER_BADGE_INVALID"},
		{ServerErrorCodeBadgeRevoked, "SERVER_BADGE_REVOKED"},
		{ServerErrorCodeTrustInsufficient, "SERVER_TRUST_INSUFFICIENT"},
		{ServerErrorCodeDIDMismatch, "SERVER_DID_MISMATCH"},
		{ServerErrorCodeIssuerUntrusted, "SERVER_ISSUER_UNTRUSTED"},
		{ServerErrorCodeOriginMismatch, "SERVER_DOMAIN_MISMATCH"},
		{ServerErrorCodePathMismatch, "SERVER_PATH_MISMATCH"},
		{ServerErrorCodeDIDResolutionFailed, "SERVER_DID_RESOLUTION_FAILED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("ServerErrorCode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrorToServerErrorCode(t *testing.T) {
	tests := []struct {
		err      error
		expected ServerErrorCode
	}{
		{ErrDIDInvalid, ServerErrorCodeDIDResolutionFailed},
		{ErrBadgeInvalid, ServerErrorCodeBadgeInvalid},
		{ErrBadgeExpired, ServerErrorCodeBadgeInvalid},
		{ErrBadgeRevoked, ServerErrorCodeBadgeRevoked},
		{ErrTrustInsufficient, ServerErrorCodeTrustInsufficient},
		{ErrDIDMismatch, ServerErrorCodeDIDMismatch},
		{ErrOriginMismatch, ServerErrorCodeOriginMismatch},
		{ErrPathMismatch, ServerErrorCodePathMismatch},
		{ErrIssuerUntrusted, ServerErrorCodeIssuerUntrusted},
		{ErrBadgeMissing, ServerErrorCodeBadgeMissing},
		{nil, ServerErrorNone},
	}

	for _, tt := range tests {
		name := "nil"
		if tt.err != nil {
			name = tt.err.Error()
		}
		t.Run(name, func(t *testing.T) {
			if got := ErrorToServerErrorCode(tt.err); got != tt.expected {
				t.Errorf("ErrorToServerErrorCode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

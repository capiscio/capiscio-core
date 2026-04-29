package envelope_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrCodeScopeInsufficient(t *testing.T) {
	assert.Equal(t, "ENVELOPE_SCOPE_INSUFFICIENT", envelope.ErrCodeScopeInsufficient)
}

func TestNewScopeInsufficientRejection(t *testing.T) {
	r := envelope.NewScopeInsufficientRejection(
		"invoice.approve",
		"invoice.read",
		"env-abc-123",
		"txn-xyz-456",
	)

	assert.Equal(t, envelope.ErrCodeScopeInsufficient, r.Error)
	assert.Equal(t, "invoice.approve", r.RequestedCapability)
	assert.Equal(t, "invoice.read", r.PresentedCapability)
	assert.Equal(t, "env-abc-123", r.EnvelopeID)
	assert.Equal(t, "txn-xyz-456", r.TxnID)
}

func TestScopeInsufficientRejection_JSON(t *testing.T) {
	r := envelope.NewScopeInsufficientRejection(
		"tools.database.write",
		"tools.database.read",
		"envelope-001",
		"txn-002",
	)

	data, err := json.Marshal(r)
	require.NoError(t, err)

	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))

	// All required fields present per RFC-008 §9.3.1.
	assert.Equal(t, "ENVELOPE_SCOPE_INSUFFICIENT", m["error"])
	assert.Equal(t, "tools.database.write", m["requested_capability"])
	assert.Equal(t, "tools.database.read", m["presented_capability"])
	assert.Equal(t, "envelope-001", m["envelope_id"])
	assert.Equal(t, "txn-002", m["txn_id"])

	// Exactly 5 fields — no policy-leaking extras.
	assert.Len(t, m, 5, "rejection payload must contain exactly the 5 RFC-mandated fields")
}

func TestScopeInsufficientRejection_JSONRoundTrip(t *testing.T) {
	original := envelope.NewScopeInsufficientRejection(
		"finance.payments",
		"finance",
		"env-rt-001",
		"txn-rt-001",
	)

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded envelope.ScopeInsufficientRejection
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Error, decoded.Error)
	assert.Equal(t, original.RequestedCapability, decoded.RequestedCapability)
	assert.Equal(t, original.PresentedCapability, decoded.PresentedCapability)
	assert.Equal(t, original.EnvelopeID, decoded.EnvelopeID)
	assert.Equal(t, original.TxnID, decoded.TxnID)
}

func TestError_ScopeInsufficient(t *testing.T) {
	err := envelope.NewError(envelope.ErrCodeScopeInsufficient, "capability does not cover requested operation")

	assert.Contains(t, err.Error(), "ENVELOPE_SCOPE_INSUFFICIENT")
	assert.Contains(t, err.Error(), "capability does not cover requested operation")

	// Works with errors.Is against another Error with same code.
	target := &envelope.Error{Code: envelope.ErrCodeScopeInsufficient}
	assert.True(t, errors.Is(err, target))

	// Does not match a different code.
	other := &envelope.Error{Code: envelope.ErrCodeExpired}
	assert.False(t, errors.Is(err, other))
}

func TestError_WrapScopeInsufficient(t *testing.T) {
	cause := errors.New("PDP denied: capability_class mismatch")
	err := envelope.WrapError(
		envelope.ErrCodeScopeInsufficient,
		"scope insufficient for requested operation",
		cause,
	)

	assert.Contains(t, err.Error(), "ENVELOPE_SCOPE_INSUFFICIENT")
	assert.Contains(t, err.Error(), "PDP denied")
	assert.ErrorIs(t, err, cause)
}

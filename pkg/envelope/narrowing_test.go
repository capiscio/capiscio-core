package envelope_test

import (
	"testing"
	"time"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateNarrowing(t *testing.T) {
	now := time.Now()
	baseParent := &envelope.Payload{
		EnvelopeID:               uuid.New().String(),
		IssuerDID:                "did:key:issuerA",
		SubjectDID:               "did:key:subjectB",
		TxnID:                    "txn-1",
		CapabilityClass:          "tools.database",
		Constraints:              map[string]any{},
		DelegationDepthRemaining: 5,
		IssuedAt:                 now.Unix(),
		ExpiresAt:                now.Add(1 * time.Hour).Unix(),
		IssuerBadgeJTI:           "badge-a",
	}

	makeChild := func(modify func(*envelope.Payload)) *envelope.Payload {
		child := &envelope.Payload{
			EnvelopeID:               uuid.New().String(),
			IssuerDID:                "did:key:subjectB", // must match parent subject
			SubjectDID:               "did:key:subjectC",
			TxnID:                    "txn-1",
			CapabilityClass:          "tools.database.read", // narrower
			Constraints:              map[string]any{},
			DelegationDepthRemaining: 4, // decremented
			IssuedAt:                 now.Unix(),
			ExpiresAt:                now.Add(30 * time.Minute).Unix(), // tighter
			IssuerBadgeJTI:           "badge-b",
		}
		if modify != nil {
			modify(child)
		}
		return child
	}

	tests := []struct {
		name    string
		modify  func(*envelope.Payload)
		wantErr string // "" = no error
	}{
		// Valid cases
		{
			name:   "valid narrowing — all dimensions tighter",
			modify: nil,
		},
		{
			name:   "same capability class is valid",
			modify: func(c *envelope.Payload) { c.CapabilityClass = "tools.database" },
		},
		{
			name: "same temporal bounds valid",
			modify: func(c *envelope.Payload) {
				c.IssuedAt = baseParent.IssuedAt
				c.ExpiresAt = baseParent.ExpiresAt
			},
		},

		// Capability class violations
		{
			name:    "broader capability rejected",
			modify:  func(c *envelope.Payload) { c.CapabilityClass = "tools" },
			wantErr: "NARROWING",
		},
		{
			name:    "unrelated capability rejected",
			modify:  func(c *envelope.Payload) { c.CapabilityClass = "files.write" },
			wantErr: "NARROWING",
		},
		{
			name:    "sibling capability rejected",
			modify:  func(c *envelope.Payload) { c.CapabilityClass = "tools.filesystem" },
			wantErr: "NARROWING",
		},

		// Temporal violations
		{
			name:    "later expiry rejected",
			modify:  func(c *envelope.Payload) { c.ExpiresAt = baseParent.ExpiresAt + 1 },
			wantErr: "NARROWING",
		},
		{
			name:    "earlier issued_at rejected",
			modify:  func(c *envelope.Payload) { c.IssuedAt = baseParent.IssuedAt - 1 },
			wantErr: "NARROWING",
		},

		// Depth violations
		{
			name:    "depth not decremented rejected",
			modify:  func(c *envelope.Payload) { c.DelegationDepthRemaining = 5 },
			wantErr: "NARROWING",
		},
		{
			name:    "depth increased rejected",
			modify:  func(c *envelope.Payload) { c.DelegationDepthRemaining = 6 },
			wantErr: "NARROWING",
		},

		// DID chain violations
		{
			name:    "broken DID chain rejected",
			modify:  func(c *envelope.Payload) { c.IssuerDID = "did:key:wrongIssuer" },
			wantErr: "CHAIN_BROKEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			child := makeChild(tt.modify)
			err := envelope.ValidateNarrowing(baseParent, child)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

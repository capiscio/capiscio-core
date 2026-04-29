package envelope_test

import (
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnforcementMode(t *testing.T) {
	tests := []struct {
		input string
		want  envelope.EnforcementMode
		err   bool
	}{
		{"EM-OBSERVE", envelope.EMObserve, false},
		{"EM-GUARD", envelope.EMGuard, false},
		{"EM-DELEGATE", envelope.EMDelegate, false},
		{"EM-STRICT", envelope.EMStrict, false},
		{"INVALID", 0, true},
		{"em-observe", 0, true}, // case-sensitive
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := envelope.ParseEnforcementMode(tt.input)
			if tt.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestEnforcementMode_String(t *testing.T) {
	assert.Equal(t, "EM-OBSERVE", envelope.EMObserve.String())
	assert.Equal(t, "EM-GUARD", envelope.EMGuard.String())
	assert.Equal(t, "EM-DELEGATE", envelope.EMDelegate.String())
	assert.Equal(t, "EM-STRICT", envelope.EMStrict.String())
}

func TestEscalate(t *testing.T) {
	tests := []struct {
		name       string
		configured envelope.EnforcementMode
		minimum    envelope.EnforcementMode
		want       envelope.EnforcementMode
	}{
		{"minimum higher", envelope.EMObserve, envelope.EMGuard, envelope.EMGuard},
		{"configured higher", envelope.EMStrict, envelope.EMGuard, envelope.EMStrict},
		{"same level", envelope.EMDelegate, envelope.EMDelegate, envelope.EMDelegate},
		{"observe + strict", envelope.EMObserve, envelope.EMStrict, envelope.EMStrict},
		{"strict + observe", envelope.EMStrict, envelope.EMObserve, envelope.EMStrict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := envelope.Escalate(tt.configured, tt.minimum)
			assert.Equal(t, tt.want, got)
		})
	}
}

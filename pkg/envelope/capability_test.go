package envelope_test

import (
	"testing"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCapabilityClass(t *testing.T) {
	tests := []struct {
		name    string
		class   string
		wantErr bool
	}{
		{"single segment", "tools", false},
		{"two segments", "tools.database", false},
		{"three segments", "tools.database.read", false},
		{"with underscore", "tools.db_read", false},
		{"with number", "tools.v2", false},
		{"complex valid", "a.b_c.d1e2", false},

		{"empty string", "", true},
		{"uppercase", "Tools", true},
		{"leading dot", ".tools", true},
		{"trailing dot", "tools.", true},
		{"double dot", "tools..database", true},
		{"starts with number", "tools.1invalid", true},
		{"contains dash", "tools.db-read", true},
		{"contains space", "tools. read", true},
		{"uppercase mixed", "tools.Database", true},
		{"starts with underscore", "tools._private", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := envelope.ValidateCapabilityClass(tt.class)
			if tt.wantErr {
				require.Error(t, err)
				var envErr *envelope.Error
				require.ErrorAs(t, err, &envErr)
				assert.Equal(t, "ENVELOPE_CAPABILITY_INVALID", envErr.Code)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIsWithinScope(t *testing.T) {
	tests := []struct {
		name   string
		child  string
		parent string
		want   bool
	}{
		{"same class", "tools", "tools", true},
		{"child is deeper", "tools.database", "tools", true},
		{"child is much deeper", "tools.database.read.query", "tools", true},
		{"exact two-level match", "tools.database", "tools.database", true},

		{"parent is deeper", "tools", "tools.database", false},
		{"unrelated class", "files.write", "tools.database", false},
		{"partial prefix but not segment boundary", "tools_extra", "tools", false},
		{"sibling", "tools.filesystem", "tools.database", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := envelope.IsWithinScope(tt.child, tt.parent)
			assert.Equal(t, tt.want, result)
		})
	}
}

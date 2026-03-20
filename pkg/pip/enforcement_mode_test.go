package pip

import (
	"os"
	"testing"
)

func TestEnforcementModeString(t *testing.T) {
	tests := []struct {
		mode EnforcementMode
		want string
	}{
		{EMObserve, "EM-OBSERVE"},
		{EMGuard, "EM-GUARD"},
		{EMDelegate, "EM-DELEGATE"},
		{EMStrict, "EM-STRICT"},
		{EnforcementMode(99), "EnforcementMode(99)"},
	}

	for _, tt := range tests {
		got := tt.mode.String()
		if got != tt.want {
			t.Errorf("EnforcementMode(%d).String() = %q, want %q", int(tt.mode), got, tt.want)
		}
	}
}

func TestParseEnforcementMode(t *testing.T) {
	tests := []struct {
		input   string
		want    EnforcementMode
		wantErr bool
	}{
		{"EM-OBSERVE", EMObserve, false},
		{"EM-GUARD", EMGuard, false},
		{"EM-DELEGATE", EMDelegate, false},
		{"EM-STRICT", EMStrict, false},
		{"em-observe", EMObserve, true}, // case-sensitive
		{"OBSERVE", EMObserve, true},
		{"", EMObserve, true},
		{"EM-INVALID", EMObserve, true},
	}

	for _, tt := range tests {
		got, err := ParseEnforcementMode(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseEnforcementMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseEnforcementMode(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestEnforcementModeOrdering(t *testing.T) {
	// RFC-008 §10.5: EM-OBSERVE < EM-GUARD < EM-DELEGATE < EM-STRICT
	modes := []EnforcementMode{EMObserve, EMGuard, EMDelegate, EMStrict}
	for i := 0; i < len(modes)-1; i++ {
		if !modes[i+1].StricterThan(modes[i]) {
			t.Errorf("%s should be stricter than %s", modes[i+1], modes[i])
		}
		if modes[i].StricterThan(modes[i+1]) {
			t.Errorf("%s should NOT be stricter than %s", modes[i], modes[i+1])
		}
	}

	// Same mode is not stricter than itself
	if EMStrict.StricterThan(EMStrict) {
		t.Error("EM-STRICT should not be stricter than itself")
	}
}

func TestEnforcementModeRoundtrip(t *testing.T) {
	// Every mode must roundtrip through String() → ParseEnforcementMode()
	modes := []EnforcementMode{EMObserve, EMGuard, EMDelegate, EMStrict}
	for _, em := range modes {
		s := em.String()
		parsed, err := ParseEnforcementMode(s)
		if err != nil {
			t.Errorf("roundtrip failed for %s: %v", s, err)
			continue
		}
		if parsed != em {
			t.Errorf("roundtrip: %s → ParseEnforcementMode → %s, want %s", s, parsed, em)
		}
	}
}

func TestEnforcementModeFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVal  string
		want    EnforcementMode
		wantErr bool
	}{
		{"unset defaults to EM-OBSERVE", "", EMObserve, false},
		{"EM-OBSERVE", "EM-OBSERVE", EMObserve, false},
		{"EM-STRICT", "EM-STRICT", EMStrict, false},
		{"invalid value", "INVALID", EMObserve, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal == "" {
				os.Unsetenv("CAPISCIO_ENFORCEMENT_MODE")
			} else {
				os.Setenv("CAPISCIO_ENFORCEMENT_MODE", tt.envVal)
				defer os.Unsetenv("CAPISCIO_ENFORCEMENT_MODE")
			}

			got, err := EnforcementModeFromEnv()
			if (err != nil) != tt.wantErr {
				t.Errorf("EnforcementModeFromEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("EnforcementModeFromEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

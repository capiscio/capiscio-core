package mcp

import (
	"testing"
)

func TestVersionConstants(t *testing.T) {
	if CoreVersion == "" {
		t.Error("CoreVersion should not be empty")
	}
	if ProtoVersion == "" {
		t.Error("ProtoVersion should not be empty")
	}

	// CoreVersion should be valid semver (parseable)
	ver := parseSimpleSemver(CoreVersion)
	if ver == nil {
		t.Errorf("CoreVersion %q is not valid semver", CoreVersion)
	}
}

func TestCheckVersionCompatibility(t *testing.T) {
	tests := []struct {
		name           string
		clientVersion  string
		wantCompatible bool
	}{
		// Compatible versions (>= 2.5.0, < 3.0.0)
		{"exact match", "2.5.0", true},
		{"patch bump", "2.5.1", true},
		{"minor bump", "2.6.0", true},
		{"minor bump high", "2.99.0", true},

		// Incompatible versions
		{"too old", "2.4.0", false},
		{"too old minor", "2.0.0", false},
		{"next major", "3.0.0", false},
		{"v1", "1.0.0", false},

		// Edge cases
		{"invalid version", "not-a-version", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compat, _ := CheckVersionCompatibility(tt.clientVersion)
			if compat != tt.wantCompatible {
				t.Errorf("CheckVersionCompatibility(%q) = %v, want %v",
					tt.clientVersion, compat, tt.wantCompatible)
			}
		})
	}
}

func TestCheckVersionCompatibility_ReturnsVersion(t *testing.T) {
	compat, version := CheckVersionCompatibility("2.5.0")

	if !compat {
		t.Error("2.5.0 should be compatible")
	}
	if version != CoreVersion {
		t.Errorf("returned version = %q, want %q", version, CoreVersion)
	}
}

func TestCheckHealth(t *testing.T) {
	status := CheckHealth()

	if status.Healthy != true {
		t.Error("CheckHealth should return healthy=true")
	}
	if status.CoreVersion != CoreVersion {
		t.Errorf("CoreVersion = %q, want %q", status.CoreVersion, CoreVersion)
	}
	if status.ProtoVersion != ProtoVersion {
		t.Errorf("ProtoVersion = %q, want %q", status.ProtoVersion, ProtoVersion)
	}
}

func TestHealthStatus_Fields(t *testing.T) {
	status := HealthStatus{
		Healthy:      true,
		CoreVersion:  "2.5.0",
		ProtoVersion: "1.0",
	}

	if !status.Healthy {
		t.Error("Healthy should be true")
	}
	if status.CoreVersion != "2.5.0" {
		t.Errorf("CoreVersion = %q, want %q", status.CoreVersion, "2.5.0")
	}
	if status.ProtoVersion != "1.0" {
		t.Errorf("ProtoVersion = %q, want %q", status.ProtoVersion, "1.0")
	}
}

func TestParseSimpleSemver(t *testing.T) {
	tests := []struct {
		input    string
		wantNil  bool
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		{"2.5.0", false, 2, 5, 0},
		{"1.0.0", false, 1, 0, 0},
		{"10.20.30", false, 10, 20, 30},
		{"invalid", true, 0, 0, 0},
		{"", true, 0, 0, 0},
		{"2.5", true, 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ver := parseSimpleSemver(tt.input)
			if tt.wantNil {
				if ver != nil {
					t.Errorf("parseSimpleSemver(%q) = %+v, want nil", tt.input, ver)
				}
			} else {
				if ver == nil {
					t.Errorf("parseSimpleSemver(%q) = nil, want version", tt.input)
				} else if ver.major != tt.wantMajor || ver.minor != tt.wantMinor || ver.patch != tt.wantPatch {
					t.Errorf("parseSimpleSemver(%q) = %d.%d.%d, want %d.%d.%d",
						tt.input, ver.major, ver.minor, ver.patch, tt.wantMajor, tt.wantMinor, tt.wantPatch)
				}
			}
		})
	}
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"2.5.0", "2.5.0", 0},
		{"2.5.1", "2.5.0", 1},
		{"2.5.0", "2.5.1", -1},
		{"2.6.0", "2.5.0", 1},
		{"3.0.0", "2.5.0", 1},
		{"1.0.0", "2.0.0", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			verA := parseSimpleSemver(tt.a)
			verB := parseSimpleSemver(tt.b)
			got := compareVersion(verA, verB)
			if got != tt.want {
				t.Errorf("compareVersion(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

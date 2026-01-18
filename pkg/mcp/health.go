package mcp

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	// CoreVersion is the capiscio-core version
	CoreVersion = "2.5.0"

	// ProtoVersion is the MCP proto schema version
	ProtoVersion = "1.0"

	// MinMCPVersion is the minimum compatible MCP SDK version (capiscio-mcp)
	// The MCP SDK has independent versioning starting from 0.1.0
	MinMCPVersion = "0.1.0"

	// MinVersion is the minimum compatible client SDK version (legacy capiscio-sdk)
	MinVersion = "2.5.0"

	// MaxVersionConstraint is the constraint for maximum compatible version
	MaxVersionConstraint = "< 3.0.0"
)

// CheckVersionCompatibility validates client/core version compatibility
// Returns true if the client version is compatible with this core version
func CheckVersionCompatibility(clientVersion string) (bool, string) {
	// Parse client version using simple semver regex
	ver := parseSimpleSemver(clientVersion)
	if ver == nil {
		return false, CoreVersion
	}

	// Handle MCP SDK versions (0.x.x) separately from legacy SDK versions (2.x.x)
	if ver.major == 0 {
		// MCP SDK versioning: accept >= 0.1.0
		minMCPVer := parseSimpleSemver(MinMCPVersion)
		if minMCPVer == nil {
			return false, CoreVersion
		}
		return compareVersion(ver, minMCPVer) >= 0, CoreVersion
	}

	// Legacy SDK versioning: >= 2.5.0 AND < 3.0.0
	minVer := parseSimpleSemver(MinVersion)
	if minVer == nil {
		return false, CoreVersion
	}

	// Check: version >= 2.5.0 AND version < 3.0.0
	if compareVersion(ver, minVer) < 0 {
		return false, CoreVersion
	}

	// Check major version is 2 (not 3+)
	if ver.major >= 3 {
		return false, CoreVersion
	}

	return true, CoreVersion
}

// semverVersion represents a parsed semantic version
type semverVersion struct {
	major int
	minor int
	patch int
}

// parseSimpleSemver parses a simple semver string (X.Y.Z)
func parseSimpleSemver(version string) *semverVersion {
	// Match X.Y.Z format (no prerelease/build metadata)
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
	match := re.FindStringSubmatch(strings.TrimSpace(version))
	if match == nil {
		return nil
	}

	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])

	return &semverVersion{major: major, minor: minor, patch: patch}
}

// compareVersion compares two versions, returning -1, 0, or 1
func compareVersion(a, b *semverVersion) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}

// HealthStatus represents the health status of the MCP service
type HealthStatus struct {
	// Healthy indicates if the service is healthy
	Healthy bool

	// CoreVersion is the capiscio-core version
	CoreVersion string

	// ProtoVersion is the proto schema version
	ProtoVersion string

	// Compatible indicates if the client version is compatible
	Compatible bool
}

// CheckHealth performs a health check and returns the status
func CheckHealth() *HealthStatus {
	return &HealthStatus{
		Healthy:      true,
		CoreVersion:  CoreVersion,
		ProtoVersion: ProtoVersion,
	}
}

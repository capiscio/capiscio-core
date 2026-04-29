package envelope

import (
	"fmt"
	"regexp"
	"strings"
)

// capabilitySegmentRegex validates a single capability class segment.
// Each segment must match [a-z][a-z0-9_]* per RFC-008 §7.
var capabilitySegmentRegex = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidateCapabilityClass checks that a capability class string is valid.
// It must be dot-delimited with each segment matching [a-z][a-z0-9_]*.
func ValidateCapabilityClass(class string) error {
	if class == "" {
		return NewError(ErrCodeCapabilityInvalid, "capability_class is required")
	}

	segments := strings.Split(class, ".")
	for i, seg := range segments {
		if seg == "" {
			return NewError(ErrCodeCapabilityInvalid,
				fmt.Sprintf("empty segment at position %d in %q", i, class))
		}
		if !capabilitySegmentRegex.MatchString(seg) {
			return NewError(ErrCodeCapabilityInvalid,
				fmt.Sprintf("invalid segment %q at position %d in %q: must match [a-z][a-z0-9_]*", seg, i, class))
		}
	}

	return nil
}

// IsWithinScope returns true if child is within the scope of parent.
// Per RFC-008 §7.2: child == parent OR child starts with parent + ".".
func IsWithinScope(child, parent string) bool {
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+".")
}

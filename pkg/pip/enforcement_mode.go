package pip

import (
	"fmt"
	"os"
)

// EnforcementMode represents the PEP enforcement strictness level.
// RFC-008 §10.5 defines the strict total order: EM-OBSERVE < EM-GUARD < EM-DELEGATE < EM-STRICT.
//
// NOTE: The iota integer values are an implementation detail, not a stable API.
// Comparisons MUST use the enum constants (EMObserve < EMStrict), never numeric literals.
type EnforcementMode int

const (
	EMObserve  EnforcementMode = iota // log only, never block
	EMGuard                            // block on verification failure, log PDP denials
	EMDelegate                         // block on verification + PDP deny, best-effort obligations
	EMStrict                           // block on everything including obligation failures
)

// enforcementModeEnvVar is the environment variable for PEP enforcement mode.
const enforcementModeEnvVar = "CAPISCIO_ENFORCEMENT_MODE"

// enforcementModeStrings maps modes to their RFC string representations.
var enforcementModeStrings = map[EnforcementMode]string{
	EMObserve:  "EM-OBSERVE",
	EMGuard:    "EM-GUARD",
	EMDelegate: "EM-DELEGATE",
	EMStrict:   "EM-STRICT",
}

// enforcementModeFromString maps RFC string representations to modes.
var enforcementModeFromString = map[string]EnforcementMode{
	"EM-OBSERVE":  EMObserve,
	"EM-GUARD":    EMGuard,
	"EM-DELEGATE": EMDelegate,
	"EM-STRICT":   EMStrict,
}

// String returns the RFC string representation of the enforcement mode.
func (em EnforcementMode) String() string {
	if s, ok := enforcementModeStrings[em]; ok {
		return s
	}
	return fmt.Sprintf("EnforcementMode(%d)", int(em))
}

// ParseEnforcementMode parses an RFC enforcement mode string.
// Returns an error if the string is not a recognized mode.
func ParseEnforcementMode(s string) (EnforcementMode, error) {
	if em, ok := enforcementModeFromString[s]; ok {
		return em, nil
	}
	return EMObserve, fmt.Errorf("unknown enforcement mode: %q (valid: EM-OBSERVE, EM-GUARD, EM-DELEGATE, EM-STRICT)", s)
}

// StricterThan returns true if em is stricter than other.
func (em EnforcementMode) StricterThan(other EnforcementMode) bool {
	return em > other
}

// EnforcementModeFromEnv reads the enforcement mode from the environment variable.
// Returns EMObserve (the safe default for rollout) if the variable is not set.
// Returns an error if the variable is set but not a valid mode.
func EnforcementModeFromEnv() (EnforcementMode, error) {
	val := os.Getenv(enforcementModeEnvVar)
	if val == "" {
		return EMObserve, nil
	}
	return ParseEnforcementMode(val)
}

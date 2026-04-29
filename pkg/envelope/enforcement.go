package envelope

import "fmt"

// EnforcementMode represents the enforcement strictness level per RFC-008 §10.
type EnforcementMode int

const (
	// EMObserve logs verification results but never blocks requests.
	EMObserve EnforcementMode = iota

	// EMGuard blocks on cryptographic failures but only logs PDP denials.
	EMGuard

	// EMDelegate blocks on crypto failures and PDP denials; logs obligation failures.
	EMDelegate

	// EMStrict blocks on all failures including obligation enforcement.
	EMStrict
)

var modeStrings = map[EnforcementMode]string{
	EMObserve:  "EM-OBSERVE",
	EMGuard:    "EM-GUARD",
	EMDelegate: "EM-DELEGATE",
	EMStrict:   "EM-STRICT",
}

var stringModes = map[string]EnforcementMode{
	"EM-OBSERVE":  EMObserve,
	"EM-GUARD":    EMGuard,
	"EM-DELEGATE": EMDelegate,
	"EM-STRICT":   EMStrict,
}

// ParseEnforcementMode converts a string to an EnforcementMode.
func ParseEnforcementMode(s string) (EnforcementMode, error) {
	if m, ok := stringModes[s]; ok {
		return m, nil
	}
	return 0, NewError(ErrCodeMalformed, fmt.Sprintf("invalid enforcement mode: %q", s))
}

// String returns the RFC-008 string representation.
func (m EnforcementMode) String() string {
	if s, ok := modeStrings[m]; ok {
		return s
	}
	return fmt.Sprintf("EnforcementMode(%d)", int(m))
}

// Escalate returns the stricter of configured and minimum modes.
// Per RFC-008 §10.5: if the envelope sets a minimum that exceeds the PEP's
// configured mode, the PEP must escalate to the minimum for that request.
func Escalate(configured, minimum EnforcementMode) EnforcementMode {
	if minimum > configured {
		return minimum
	}
	return configured
}

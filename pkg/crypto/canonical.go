// Package crypto provides cryptographic utilities for CapiscIO.
package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
)

// CreateCanonicalJSON creates a canonical JSON representation of the Agent Card
// for signature verification. It removes the "signatures" field and ensures
// keys are sorted (which encoding/json does by default).
func CreateCanonicalJSON(card *agentcard.AgentCard) ([]byte, error) {
	// 1. Marshal to JSON first to get the raw map structure
	// This ensures we respect the json tags in the struct
	data, err := json.Marshal(card)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal agent card: %w", err)
	}

	// 2. Unmarshal into a map to manipulate fields
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal into map: %w", err)
	}

	// 3. Remove the signatures field
	delete(rawMap, "signatures")

	// 4. Marshal back to JSON
	// encoding/json sorts map keys by default, providing canonicalization
	canonical, err := json.Marshal(rawMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create canonical json: %w", err)
	}

	return canonical, nil
}

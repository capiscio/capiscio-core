// Package crypto provides cryptographic utilities for CapiscIO.
package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/capiscio/capiscio-core/v2/pkg/agentcard"
	"github.com/gowebpki/jcs"
)

// CreateCanonicalJSON creates the canonical JSON representation of an Agent
// Card, which is the payload an Agent Card signature is computed over.
//
// A2A specification section 8.4.1 requires the payload to be canonicalized
// with the JSON Canonicalization Scheme (RFC 8785) once the `signatures`
// field has been removed.
//
// Two things this deliberately does not do, both of which previously produced
// a payload that differed from the signer's:
//
//   - It does not use encoding/json as a canonicalizer. Go sorts object keys
//     by UTF-8 byte order where RFC 8785 sorts by UTF-16 code unit, and Go's
//     encoder escapes '<', '>' and '&' where RFC 8785 emits them literally.
//     An ampersand in a URL query string was enough to break verification.
//   - It does not round-trip the document through the AgentCard struct when
//     the original bytes are available. `omitempty` on a plain bool drops a
//     field the sender explicitly set to false, and section 8.4.1 requires an
//     explicitly set field to survive canonicalization even when it holds a
//     default value.
//
// When the card was decoded from JSON, the bytes it was decoded from are used.
// When it was constructed programmatically there is nothing better available
// than the struct, and field presence is then only as faithful as the struct
// tags allow.
//
// It returns an error rather than a payload for a document that cannot be
// canonicalized: one that is not a JSON object, or one carrying a number
// outside the IEEE 754 double range that RFC 8785 defines number formatting
// over. Neither can be signed or verified meaningfully.
func CreateCanonicalJSON(card *agentcard.AgentCard) ([]byte, error) {
	source := card.Raw()
	if len(source) == 0 {
		marshaled, err := json.Marshal(card)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal agent card: %w", err)
		}
		source = marshaled
	}

	withoutSignatures, err := stripSignatures(source)
	if err != nil {
		return nil, err
	}

	canonical, err := jcs.Transform(withoutSignatures)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize agent card (RFC 8785): %w", err)
	}

	return canonical, nil
}

// stripSignatures removes the top-level `signatures` field, which is excluded
// from the signed payload to avoid a circular dependency (spec 8.4.1).
//
// Decoding uses UseNumber so numeric literals survive as their original text
// rather than being widened to float64. RFC 8785 defines its own number
// formatting and needs the value, not Go's rendering of it.
func stripSignatures(document []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()

	var fields map[string]interface{}
	if err := decoder.Decode(&fields); err != nil {
		return nil, fmt.Errorf("failed to parse agent card: %w", err)
	}

	// A JSON `null` decodes into a nil map without error, and would go on to
	// canonicalize as the four bytes "null". That is a signable payload for a
	// document that is not an agent card, so reject it here rather than hand
	// it to a signer or a verifier.
	if fields == nil {
		return nil, fmt.Errorf("agent card is not a JSON object")
	}

	delete(fields, "signatures")

	remarshaled, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode agent card: %w", err)
	}

	// Any escaping introduced here is undone by jcs.Transform, which reparses
	// the document and re-emits it per RFC 8785.
	return remarshaled, nil
}

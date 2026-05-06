package gateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/capiscio/capiscio-core/v2/pkg/envelope"
)

// Header names for RFC-008 §15 / Appendix A chain transport.
const (
	// HeaderAuthority carries the leaf Authority Envelope JWS.
	HeaderAuthority = "X-Capiscio-Authority"

	// HeaderAuthorityChain carries the base64url-encoded JSON array of JWS strings (root→leaf).
	HeaderAuthorityChain = "X-Capiscio-Authority-Chain"

	// HeaderBadgeMap carries the base64url-encoded JSON object mapping DID→badge JWS.
	HeaderBadgeMap = "X-Capiscio-Badge-Map"
)

// ExtractLeafAuthority returns the X-Capiscio-Authority header value (single JWS string).
// Returns empty string if the header is absent.
func ExtractLeafAuthority(r *http.Request) string {
	return r.Header.Get(HeaderAuthority)
}

// ExtractAuthorityChain decodes X-Capiscio-Authority-Chain (base64url JSON array of JWS strings).
// Returns nil, nil if the header is absent (single-envelope request).
// Returns an error on malformed base64url or JSON.
func ExtractAuthorityChain(r *http.Request) ([]string, error) {
	raw := r.Header.Get(HeaderAuthorityChain)
	if raw == "" {
		return nil, nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, envelope.NewError(envelope.ErrCodeMalformed,
			fmt.Sprintf("failed to decode %s: %v", HeaderAuthorityChain, err))
	}

	var chain []string
	if err := json.Unmarshal(decoded, &chain); err != nil {
		return nil, envelope.NewError(envelope.ErrCodeMalformed,
			fmt.Sprintf("failed to parse %s JSON: %v", HeaderAuthorityChain, err))
	}

	if len(chain) == 0 {
		return nil, envelope.NewError(envelope.ErrCodeMalformed,
			fmt.Sprintf("%s is an empty array", HeaderAuthorityChain))
	}

	return chain, nil
}

// ExtractBadgeMap decodes X-Capiscio-Badge-Map (base64url JSON object, DID → badge JWS).
// Returns nil, nil if the header is absent.
// Returns an error on malformed base64url or JSON.
func ExtractBadgeMap(r *http.Request) (map[string]string, error) {
	raw := r.Header.Get(HeaderBadgeMap)
	if raw == "" {
		return nil, nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, envelope.NewError(envelope.ErrCodeMalformed,
			fmt.Sprintf("failed to decode %s: %v", HeaderBadgeMap, err))
	}

	var badgeMap map[string]string
	if err := json.Unmarshal(decoded, &badgeMap); err != nil {
		return nil, envelope.NewError(envelope.ErrCodeMalformed,
			fmt.Sprintf("failed to parse %s JSON: %v", HeaderBadgeMap, err))
	}

	return badgeMap, nil
}

// ValidateChainLeafConsistency verifies that the last element of the chain array
// matches the leaf authority header (Appendix A backward compatibility requirement).
func ValidateChainLeafConsistency(leafJWS string, chain []string) error {
	if len(chain) > 0 && chain[len(chain)-1] != leafJWS {
		return envelope.NewError(envelope.ErrCodeChainBroken,
			"X-Capiscio-Authority-Chain last element does not match X-Capiscio-Authority")
	}
	return nil
}

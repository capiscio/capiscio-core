package did

// Document represents a DID Document (W3C DID Core §4).
// Only the fields needed for key resolution are included.
type Document struct {
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
}

// VerificationMethod represents a key in a DID Document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
	PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
}

// JWK represents a JSON Web Key (RFC 7517).
// Only Ed25519 (OKP curve) is currently supported.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"` // base64url-encoded public key
}

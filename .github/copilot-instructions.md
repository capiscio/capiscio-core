# capiscio-core - GitHub Copilot Instructions

## Repository Purpose

**capiscio-core** is the canonical Go implementation of CapiscIO's validation engine and CLI. It provides:
- Badge verification and validation
- DID resolution and JWKS operations
- Gateway functionality (sidecar mode)
- CLI tools for developers

**Current Version**: v2.2.0 ✅

## Architecture

```
capiscio-core/
├── cmd/
│   └── capiscio/           # CLI entry point
├── pkg/
│   ├── badge/              # Badge operations
│   │   ├── schema.go       # Badge structure (RFC-002 + RFC-003)
│   │   ├── verify.go       # Signature verification
│   │   └── validate.go     # Trust level validation
│   ├── did/                # DID resolution
│   │   ├── resolver.go     # Multi-method resolver
│   │   └── web.go          # did:web support
│   ├── gateway/            # Gateway/sidecar mode
│   │   ├── proxy.go        # HTTP proxy
│   │   └── validator.go    # Badge validation middleware
│   └── jwks/               # JWKS operations
│       ├── fetch.go        # Fetch public keys
│       └── verify.go       # JWS verification
├── internal/
│   └── cli/                # CLI commands implementation
└── bindings/               # Language bindings (optional)
```

## Critical Development Rules

### 1. RFC Compliance

**RFC-002: Trust Badge Specification**
- Badge MUST be JWS compact format
- MUST have `iss`, `sub`, `jti`, `exp`, `iat` claims
- MUST use Ed25519 signatures
- Trust level 0-4 validation

**RFC-003: Key Ownership Proof**
- IAL-1 badges MUST have `cnf` claim with JWK
- Challenge signatures use agent's private key
- Verification against DID Document public key

### 2. Package Structure

**CLI Pattern (cmd/capiscio/)**
```go
func main() {
    rootCmd := cli.NewRootCommand()
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
```

**Library Pattern (pkg/)**
- Public API in pkg/ packages
- Internal implementation in internal/
- Each package has clear responsibility

### 3. Error Handling

**Use custom error types:**
```go
type BadgeValidationError struct {
    Reason string
    Badge  *Badge
}

func (e *BadgeValidationError) Error() string {
    return fmt.Sprintf("badge validation failed: %s", e.Reason)
}
```

**Return errors, don't panic:**
```go
// GOOD
func VerifyBadge(token string) (*Badge, error) {
    if token == "" {
        return nil, fmt.Errorf("token is empty")
    }
    // ...
}

// BAD
func VerifyBadge(token string) *Badge {
    if token == "" {
        panic("token is empty")
    }
    // ...
}
```

### 4. Testing Requirements

**Unit Tests (80%+ coverage)**
```go
func TestVerifyBadge_ValidSignature(t *testing.T) {
    // Arrange
    badge := generateTestBadge()
    
    // Act
    result, err := badge.Verify()
    
    // Assert
    assert.NoError(t, err)
    assert.True(t, result.Valid)
}
```

**Table-Driven Tests**
```go
func TestParseBadge(t *testing.T) {
    tests := []struct {
        name    string
        token   string
        wantErr bool
    }{
        {"valid JWS", "eyJ...", false},
        {"invalid format", "not-a-jws", true},
        {"empty token", "", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := ParseBadge(tt.token)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseBadge() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### 5. Badge Verification Flow

```go
// Step 1: Parse JWS
badge, err := badge.ParseBadge(token)
if err != nil {
    return nil, fmt.Errorf("failed to parse badge: %w", err)
}

// Step 2: Fetch JWKS from issuer
jwks, err := jwks.Fetch(badge.Issuer + "/.well-known/jwks.json")
if err != nil {
    return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
}

// Step 3: Verify signature
valid, err := badge.VerifySignature(jwks)
if err != nil || !valid {
    return nil, fmt.Errorf("signature verification failed")
}

// Step 4: Validate claims
if err := badge.ValidateClaims(); err != nil {
    return nil, fmt.Errorf("invalid claims: %w", err)
}

// Step 5: Check revocation (optional)
revoked, err := badge.CheckRevocation()
if err != nil {
    return nil, fmt.Errorf("revocation check failed: %w", err)
}
```

### 6. DID Resolution

**Supported Methods:**
- `did:web` - Web-based DIDs
- `did:key` - Cryptographic key DIDs

**Resolution Pattern:**
```go
type DIDResolver interface {
    Resolve(did string) (*DIDDocument, error)
}

type DidWebResolver struct {
    httpClient *http.Client
}

func (r *DidWebResolver) Resolve(did string) (*DIDDocument, error) {
    // did:web:registry.capisc.io:agents:agent-123
    // -> https://registry.capisc.io/agents/agent-123/did.json
    
    url, err := didWebToURL(did)
    if err != nil {
        return nil, err
    }
    
    resp, err := r.httpClient.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var doc DIDDocument
    if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
        return nil, err
    }
    
    return &doc, nil
}
```

### 7. CLI Command Pattern

```go
func NewVerifyCommand() *cobra.Command {
    var (
        issuerURL string
        verbose   bool
    )
    
    cmd := &cobra.Command{
        Use:   "verify <badge-token>",
        Short: "Verify a trust badge",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            token := args[0]
            
            result, err := badge.Verify(token, issuerURL)
            if err != nil {
                return fmt.Errorf("verification failed: %w", err)
            }
            
            if verbose {
                printVerboseResult(result)
            } else {
                fmt.Println("Valid:", result.Valid)
            }
            
            return nil
        },
    }
    
    cmd.Flags().StringVar(&issuerURL, "issuer", "", "Expected issuer URL")
    cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
    
    return cmd
}
```

## Common Development Tasks

### Building

```bash
# Build CLI
make build-cli

# Build library
make build-lib

# Build both
make build
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package
go test -v ./pkg/badge/...

# Run with race detector
go test -race ./...
```

### Linting

```bash
# Run golangci-lint
make lint

# Format code
make fmt
```

### Releasing

```bash
# Tag release
git tag v2.2.0
git push origin v2.2.0

# Build binaries
make release
```

## Key Structs and Interfaces

### Badge (pkg/badge/schema.go)

```go
type Badge struct {
    // Standard JWT claims
    Issuer    string    `json:"iss"`           // CA URL
    Subject   string    `json:"sub"`           // Agent DID
    TokenID   string    `json:"jti"`           // UUID
    ExpiresAt int64     `json:"exp"`           // Unix timestamp
    IssuedAt  int64     `json:"iat"`           // Unix timestamp
    NotBefore int64     `json:"nbf,omitempty"` // Optional
    
    // RFC-002 claims
    TrustLevel int      `json:"trust_level"`   // 0-4
    
    // RFC-003 claims (IAL-1)
    IAL        int      `json:"ial,omitempty"` // Identity assurance level
    CNF        *CNF     `json:"cnf,omitempty"` // Confirmation claim
}

type CNF struct {
    JWK *JWK `json:"jwk"` // Agent's public key
}
```

### DID Document (pkg/did/)

```go
type DIDDocument struct {
    Context            []string                `json:"@context"`
    ID                 string                  `json:"id"`
    VerificationMethod []VerificationMethod    `json:"verificationMethod"`
    Authentication     []string                `json:"authentication"`
}

type VerificationMethod struct {
    ID                 string `json:"id"`
    Type               string `json:"type"`
    Controller         string `json:"controller"`
    PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
    PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}
```

## Environment Variables

```bash
# Gateway mode
CAPISCIO_ISSUER_URL="https://registry.capisc.io"
CAPISCIO_MIN_TRUST_LEVEL="1"  # Don't accept self-signed
CAPISCIO_CACHE_TTL="300"       # 5 minutes

# Development
CAPISCIO_DEV_MODE="true"       # Accept self-signed badges
CAPISCIO_LOG_LEVEL="debug"
```

## Dependencies

**Required:**
- `github.com/spf13/cobra` - CLI framework
- `github.com/lestrrat-go/jwx` - JWS/JWT operations
- `golang.org/x/crypto` - Ed25519 signatures

**Optional:**
- `github.com/stretchr/testify` - Testing utilities
- `github.com/rs/zerolog` - Structured logging

## Code Quality Standards

### 1. Follow Go conventions
- Use `gofmt` for formatting
- Follow effective Go guidelines
- Use meaningful variable names

### 2. Document exported functions
```go
// VerifyBadge verifies the signature and claims of a trust badge.
// It returns the parsed badge and any validation errors.
//
// The verification process:
// 1. Parses the JWS token
// 2. Fetches the issuer's JWKS
// 3. Verifies the signature
// 4. Validates claims (expiration, issuer, etc.)
func VerifyBadge(token string, issuerURL string) (*Badge, error) {
    // ...
}
```

### 3. Use interfaces for flexibility
```go
type BadgeVerifier interface {
    Verify(token string) (*Badge, error)
}

type JWKSFetcher interface {
    Fetch(url string) (*JWKS, error)
}
```

### 4. Prefer composition over inheritance
```go
type GatewayValidator struct {
    verifier BadgeVerifier
    resolver DIDResolver
    cache    Cache
}

func (g *GatewayValidator) ValidateRequest(req *http.Request) error {
    token := extractBadge(req)
    badge, err := g.verifier.Verify(token)
    // ...
}
```

## Common Pitfalls

1. **Don't skip signature verification** - Always verify JWS
2. **Don't accept expired badges** - Check `exp` claim
3. **Don't trust self-signed in production** - Check trust level
4. **Don't ignore errors** - Always handle errors properly
5. **Don't use global state** - Pass dependencies explicitly
6. **Don't skip tests** - Maintain 80%+ coverage

## Version Alignment

This package MUST stay aligned with:
- capiscio-python v2.2.0
- capiscio-node v2.2.0
- validate-a2a (uses this version)

When releasing, update:
1. `cmd/capiscio/main.go` version constant
2. `README.md` version badges
3. Git tag (v2.2.0)
4. GitHub release notes

## References

- RFC-002: https://github.com/capiscio/capiscio-rfcs/blob/main/docs/002-trust-badge.md
- RFC-003: https://github.com/capiscio/capiscio-rfcs/blob/main/docs/003-key-ownership-proof.md
- Go best practices: https://go.dev/doc/effective_go
- JWS spec: https://datatracker.ietf.org/doc/html/rfc7515

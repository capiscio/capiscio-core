# capiscio-core - GitHub Copilot Instructions

## � ABSOLUTE RULES - NO EXCEPTIONS

These rules are non-negotiable. Violating them will cause production issues.

### 1. ALL WORK VIA PULL REQUESTS
- **NEVER commit directly to `main`.** All changes MUST go through PRs.
- Create feature branches: `feature/`, `fix/`, `chore/`
- PRs require CI to pass before merge consideration

### 2. LOCAL CI VALIDATION BEFORE PUSH
- **ALL tests MUST pass locally before pushing to a PR.**
- Run: `make test` or `go test ./...`
- If tests fail locally, fix them before pushing. Never push failing code.

### 3. RFCs ARE READ-ONLY
- **DO NOT modify RFCs without explicit team authorization.**
- Implementation must conform to RFCs in `capiscio-rfcs/`

### 4. NO WATCH/BLOCKING COMMANDS
- **NEVER run blocking commands** without timeout
- Use `timeout` wrapper for long-running commands

---

## �🚨 CRITICAL: Read First

**Before starting work, read the workspace context files:**
1. `../../.context/CURRENT_SPRINT.md` - Sprint goals and priorities
2. `../../.context/ACTIVE_TASKS.md` - Active tasks (check for conflicts)
3. `../../.context/SESSION_LOG.md` - Recent session history

**After significant work, update:**
- `../../.context/ACTIVE_TASKS.md` - Update task status
- `../../.context/SESSION_LOG.md` - Log what was done

---

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
│   │   ├── verifier.go     # Signature and trust verification
│   │   ├── issuer.go       # Badge issuance logic
│   │   ├── keeper.go       # State management and persistence
│   │   ├── client.go       # Client-facing badge helpers
│   │   └── errors.go       # Badge-specific error types
│   ├── did/                # DID resolution
│   │   └── did.go          # did:web and did:key support
│   ├── crypto/             # Cryptographic utilities & JWKS operations
│   │   ├── jwks.go         # JWKS fetch/caching and key management
│   │   └── verifier.go     # JWS verification
│   ├── gateway/            # Gateway/sidecar mode
│   │   └── middleware.go   # Badge validation middleware
├── internal/
│   └── rpc/                # Internal RPC utilities
└── bindings/               # Language bindings (optional)
```

## Critical Development Rules

### 1. RFC Compliance

**RFC-002: Trust Badge Specification**
- Badge MUST be JWS compact format
- MUST have `iss`, `sub`, `jti`, `exp`, `iat` claims
- MUST use Ed25519 signatures
- Trust level "0"-"3" validation (stored as strings; level "4" is reserved/not yet implemented)

**RFC-003: Key Ownership Proof**
- IAL-1 badges MUST have `cnf` claim with JWK
- Challenge signatures use agent's private key
- Verification against DID Document public key

### 2. Package Structure

**CLI Pattern (cmd/capiscio/)**
```go
// Actual implementation uses global rootCmd with subcommands
// added via init() functions in badge.go, gateway.go, key.go, etc.
var rootCmd = &cobra.Command{
    Use:   "capiscio",
    Short: "CapiscIO CLI for badge verification and gateway operations",
}

func main() {
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
// The Verifier type (see pkg/badge/verifier.go) encapsulates:
//   - badge parsing
//   - JWKS lookup and key resolution (via pkg/crypto/)
//   - signature verification
//   - claim validation
//   - optional revocation checks
verifier := badge.Verifier{}

// Verify performs all verification steps and returns a validated badge
// or an error if any step fails.
validatedBadge, err := verifier.Verify(ctx, rawBadgeJWT)
if err != nil {
    return nil, fmt.Errorf("badge verification failed: %w", err)
}

return validatedBadge, nil
```

### 6. DID Resolution

**Supported Methods:**
- `did:web` - Web-based DIDs
- `did:key` - Cryptographic key DIDs

**Resolution Pattern:**
```go
// DID resolution is driven by the shared parser in pkg/did.
// did:web DIDs are converted to HTTPS URLs by did.Parse(), rather than
// via a dedicated resolver interface/struct.
//
// Example:
//
//   did:web:registry.capisc.io:agents:agent-123
//   -> https://registry.capisc.io/agents/agent-123/did.json
//
// Callers use did.Parse to obtain the information needed to fetch the
// DID Document with their HTTP client.

import "github.com/capiscio/capiscio-core/v2/pkg/did"

func resolveDIDWeb(raw string) (*DIDDocument, error) {
    // Parse the DID using the canonical parser.
    parsed, err := did.Parse(raw)
    if err != nil {
        return nil, err
    }

    // parsed now encodes the HTTPS URL for did:web DIDs according to
    // pkg/did's logic. Use that URL with your HTTP client to retrieve
    // the DID Document (did.json) and decode it into a DIDDocument.
    //
    // This function is illustrative; wire it to your HTTP client as needed.
    return nil, nil
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

### Claims (pkg/badge/schema.go)

```go
// Claims represents the JWT claims used for CapiscIO badges.
type Claims struct {
    // Standard JWT claims
    JTI      string `json:"jti"` // JWT ID (UUID)
    Issuer   string `json:"iss"` // CA URL
    Subject  string `json:"sub"` // Agent DID
    Expiry   int64  `json:"exp"` // Unix timestamp
    IssuedAt int64  `json:"iat"` // Unix timestamp

    // RFC-003 claims (IAL-1)
    IAL string `json:"ial,omitempty"` // Identity assurance level
    CNF *ConfirmationClaim `json:"cnf,omitempty"` // Confirmation claim

    // Verifiable Credential payload
    VC VerifiableCredential `json:"vc"`
}

// ConfirmationClaim represents the "cnf" confirmation claim.
type ConfirmationClaim struct {
    KID string           `json:"kid,omitempty"` // Key ID reference
    JWK *jose.JSONWebKey `json:"jwk,omitempty"` // Embedded agent public key
    JKT string           `json:"jkt,omitempty"` // JWK thumbprint
}

// Note: Trust level is not a direct field on Claims.
// It is encoded as a string "0", "1", "2", or "3" in:
//   Claims.VC.CredentialSubject.Level
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
- `github.com/go-jose/go-jose/v4` - JWS/JWT operations
- `golang.org/x/crypto` - Ed25519 signatures
- `google.golang.org/grpc` - gRPC server/client

**Optional:**
- `github.com/stretchr/testify` - Testing utilities

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

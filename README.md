# CapiscIO Core: The Authority Layer

[![Go Reference](https://pkg.go.dev/badge/github.com/capiscio/capiscio-core.svg)](https://pkg.go.dev/github.com/capiscio/capiscio-core)
[![CI](https://github.com/capiscio/capiscio-core/actions/workflows/ci.yml/badge.svg)](https://github.com/capiscio/capiscio-core/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/capiscio/capiscio-core)](https://goreportcard.com/report/github.com/capiscio/capiscio-core)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/capiscio/capiscio-core?sort=semver)](https://github.com/capiscio/capiscio-core/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**CapiscIO Core** is the **Universal Authority Layer** for AI Agents. It provides the infrastructure to Issue, Verify, and Enforce **Trust Badges** (Identity) for any agent, regardless of protocol (REST, MCP, A2A, etc.).

While it serves as the reference implementation for the **Agent-to-Agent (A2A) Protocol**, its primary mission is to secure the broader agent ecosystem.

> **v1.1.0 Release**: Full implementation of **RFC-002 Trust Badge Specification** with did:web DIDs, Trust Levels, and enhanced verification.

## Why CapiscIO?

Building authentication for AI Agents is hard. OAuth is complex, API keys are insecure, and building a custom registry is a distraction.

**CapiscIO Core** acts as a **Security Sidecar**. It sits in front of your agent, verifies incoming requests against a trusted registry, and forwards only authenticated traffic.

```text
[Client] --(Badge)--> [CapiscIO Gateway] --(Identity)--> [Your Agent]
                            |
                       (Verify Sig)
                            |
                       [Registry]
```

## Key Features

*   **Trust Badges (RFC-002)**: Issue and Verify VC-aligned JWS tokens with did:web DIDs and Trust Levels (DV/OV/EV).
*   **Gateway Sidecar**: A high-performance Reverse Proxy that enforces identity before traffic reaches your Agent.
*   **Registry Interface**: Pluggable trust anchors supporting **Local Mode** (Air-gapped/Dev), **Offline Mode** (Trust Store), and **Cloud Mode** (Enterprise).
*   **Go-Native**: Built for speed and concurrency, deployable as a single static binary.

## ⚡ Quick Start (The "Minimal Stack")

### 1. Installation

```bash
go install github.com/capiscio/capiscio-core/cmd/capiscio@latest
```

### 2. Issue a Trust Badge (Identity)

**Self-Signed (Development)**
```bash
# Level 1 (Domain Validated) - default
capiscio badge issue --self-sign --domain example.com

# Level 2 (Organization Validated)
capiscio badge issue --self-sign --level 2 --domain mycompany.com

# With audience restriction
capiscio badge issue --self-sign --aud "https://api.example.com"
```

**With Persistent Key (Production)**
```bash
# 1. Generate a Key Pair
capiscio key gen --out-priv private.jwk --out-pub public.jwk

# 2. Issue a Badge using the Private Key
capiscio badge issue --key private.jwk --sub "did:web:registry.capisc.io:agents:prod"
```

**Automated Renewal (Daemon)**
```bash
capiscio badge keep \
  --key private.jwk \
  --sub "did:web:registry.capisc.io:agents:prod" \
  --out badge.jwt \
  --exp 5m \
  --renew-before 1m
```

### 3. Verify a Badge

```bash
# Online verification (fetches CA key from issuer)
capiscio badge verify "$TOKEN"

# Offline verification (uses local trust store)
capiscio badge verify "$TOKEN" --offline

# With audience check
capiscio badge verify "$TOKEN" --audience "https://api.example.com"
```

### 4. Manage Trust Store (Offline Mode)

```bash
# Add CA keys from JWKS endpoint
capiscio trust add --from-jwks https://registry.capisc.io/.well-known/jwks.json

# List trusted keys
capiscio trust list

# Remove a key
capiscio trust remove <kid>
```

### 5. Start the Gateway (Enforcement)

```bash
capiscio gateway start \
  --port 8080 \
  --target http://localhost:3000 \
  --local-key public-key.json
```

### 6. Make a Request

```bash
# This will succeed (200 OK)
curl -H "X-Capiscio-Badge: $(cat badge.jwt)" http://localhost:8080/api/v1/agent

# This will fail (401 Unauthorized)
curl http://localhost:8080/api/v1/agent
```

## 🔐 Trust Levels (RFC-002)

Trust Badges include a **Trust Level** claim that indicates the verification depth:

| Level | Name | Verification |
|-------|------|--------------|
| 1 | DV (Domain Validated) | Domain ownership verified |
| 2 | OV (Organization Validated) | Organization identity verified |
| 3 | EV (Extended Validation) | Extended identity verification |

```bash
# Issue with specific trust level
capiscio badge issue --self-sign --level 2
```

## 🌐 DID:Web Integration

Badges use **did:web** DIDs for agent identity:

```
did:web:registry.capisc.io:agents:my-agent-123
```

The `pkg/did` package provides utilities for parsing and constructing DIDs:

```go
import "github.com/capiscio/capiscio-core/pkg/did"

// Parse a DID
d, err := did.Parse("did:web:registry.capisc.io:agents:my-agent")

// Get the DID Document URL
url := d.DocumentURL() // https://registry.capisc.io/agents/my-agent/did.json

// Create a new agent DID
agentDID := did.NewCapiscIOAgentDID("my-agent-123")
```

## 🌍 Universal Compatibility

While `capiscio-core` is the reference implementation for the **A2A Protocol**, the **Authority Layer** is designed to be **Protocol Agnostic**.

*   **Any Agent**: The Gateway works with any HTTP-based agent (REST, GraphQL, MCP, etc.).
*   **Any Identity**: The Trust Badge is a standard JWT/VC that can wrap any DID.
*   **Any Transport**: Badges are passed via standard HTTP headers (`Authorization` or `X-Capiscio-Badge`).

You can use the **Gateway** to secure *any* AI Agent, even if it doesn't fully implement the A2A Agent Card specification.

## 🏗️ Architecture

### The Authority Layer
*   **Trust Badge**: A standard JWS containing Identity (`sub`), Trust Level, and Capabilities (`vc`).
*   **Gateway**: A reverse proxy that enforces badge validity before forwarding traffic.
*   **Registry**: The source of truth for public keys (Local, Trust Store, or Cloud).
*   **Trust Store**: Local storage for CA keys enabling offline verification.
*   **Revocation Cache**: Local cache for revocation lists (5-minute staleness per RFC-002).

### The Validation Engine (Foundation)
CapiscIO Core retains its original capabilities as a robust validator for the A2A Protocol:
*   **Agent Card Validation**: Deep schema validation for `agent-card.json` files.
*   **Scoring Engine**: Calculates "Trust Scores" based on compliance, identity proof, and availability.
*   **Protocol Clients**: Built-in JSON-RPC and HTTP clients for testing Agent availability.

## 📚 Library Usage

### 1. Authority Layer (Gatekeeper)

```go
import (
    "github.com/capiscio/capiscio-core/pkg/badge"
    "github.com/capiscio/capiscio-core/pkg/registry"
)

func main() {
    // 1. Setup Registry
    reg := registry.NewLocalRegistry("./keys/public.jwk")
    
    // 2. Create Verifier
    verifier := badge.NewVerifier(reg)
    
    // 3. Verify a Token (simple)
    claims, err := verifier.Verify(context.Background(), tokenString)
    if err != nil {
        log.Fatal("Invalid badge")
    }
    
    fmt.Printf("Authenticated Agent: %s\n", claims.Subject)
}
```

### 2. Advanced Verification (RFC-002)

```go
import (
    "github.com/capiscio/capiscio-core/pkg/badge"
)

func main() {
    verifier := badge.NewVerifier(reg)
    
    // Verify with options
    result, err := verifier.VerifyWithOptions(ctx, tokenString, badge.VerifyOptions{
        Mode:           badge.VerifyModeOffline,  // Use trust store
        TrustedIssuers: []string{"https://registry.capisc.io"},
        Audience:       "https://api.example.com",
    })
    if err != nil {
        var badgeErr *badge.BadgeError
        if errors.As(err, &badgeErr) {
            fmt.Printf("Badge error: %s (code: %s)\n", badgeErr.Message, badgeErr.Code)
        }
    }
    
    fmt.Printf("Trust Level: %s\n", result.Claims.TrustLevel())
}
```

### 3. Validation Engine (Compliance)

```go
import (
    "github.com/capiscio/capiscio-core/pkg/agentcard"
    "github.com/capiscio/capiscio-core/pkg/scoring"
)

func main() {
    engine := scoring.NewEngine(nil)
    card := &agentcard.AgentCard{...}

    result, err := engine.Validate(context.Background(), card, true)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Compliance Score: %.2f\n", result.TrustScore)
}
```

## 📦 Packages

| Package | Description |
|---------|-------------|
| `pkg/badge` | Trust Badge issuance, verification, and error handling |
| `pkg/did` | did:web parsing and construction |
| `pkg/trust` | Local trust store for CA keys |
| `pkg/revocation` | Revocation list caching |
| `pkg/registry` | Registry interface (Local, Cloud) |
| `pkg/gateway` | HTTP Gateway middleware |
| `pkg/agentcard` | Agent Card schema and validation |
| `pkg/scoring` | Trust scoring engine |
| `pkg/crypto` | JWKS fetching and key utilities |

## CLI Reference

### `badge issue`
Issue a new Trust Badge.

```bash
capiscio badge issue --self-sign --level 2 --domain example.com
```

**Flags:**
*   `--self-sign`: Self-sign for development (explicit flag required).
*   `--level`: Trust level: 1 (DV), 2 (OV), or 3 (EV). Default: 1.
*   `--domain`: Agent domain. Default: example.com.
*   `--sub`: Subject DID (did:web format).
*   `--aud`: Audience (comma-separated URLs).
*   `--exp`: Expiration duration. Default: 5m (per RFC-002).
*   `--key`: Path to private key file (JWK).
*   `--iss`: Issuer URL.

### `badge verify`
Verify a Trust Badge.

```bash
capiscio badge verify "$TOKEN" --offline
```

**Flags:**
*   `--offline`: Offline mode (uses trust store).
*   `--key`: Path to public key file (JWK).
*   `--trusted-issuers`: Comma-separated list of trusted issuer URLs.
*   `--audience`: Verifier's identity for audience validation.
*   `--skip-revocation`: Skip revocation check (testing only).
*   `--skip-agent-status`: Skip agent status check (testing only).

### `trust`
Manage the local trust store.

```bash
capiscio trust add --from-jwks https://registry.capisc.io/.well-known/jwks.json
capiscio trust list
capiscio trust remove <kid>
```

### `validate`
Validates an Agent Card file or URL.

```bash
capiscio validate ./agent-card.json
```

**Flags:**
*   `--json`: Output results as JSON.
*   `--strict`: Enable strict validation mode (fails on warnings).
*   `--test-live`: Perform live availability checks.
*   `--skip-signature`: Skip JWS signature verification.
*   `--schema-only`: Validate schema only, skip endpoint testing.
*   `--errors-only`: Show only errors and warnings.
*   `--timeout`: Request timeout (default 10s).

## Development

### Prerequisites
- Go 1.21+

### Testing
```bash
go test ./pkg/...
```

### Building
```bash
go build ./cmd/capiscio
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

# CapiscIO Core: The Authority Layer

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
# Level 0 (Self-Signed) - for development only
capiscio badge issue --self-sign

# With explicit domain
capiscio badge issue --self-sign --domain example.com

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

# Accept self-signed for development
capiscio badge verify "$TOKEN" --accept-self-signed

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

| Level | Name | Verification | DID Method |
|-------|------|--------------|------------|
| 0 | SS (Self-Signed) | No external validation | `did:key` |
| 1 | DV (Domain Validated) | Domain ownership verified | `did:web` |
| 2 | OV (Organization Validated) | Organization identity verified | `did:web` |
| 3 | EV (Extended Validation) | Extended identity verification | `did:web` |
| 4 | CV (Community Vouched) | Peer attestations verified | `did:web` |

```bash
# Issue Level 0 (Self-Signed) - for development only
capiscio badge issue --self-sign
# Note: --self-sign implies level 0 and uses did:key

# Issue Level 2 (OV) - requires CA key
capiscio badge issue --key ca-private.jwk --level 2 --domain example.com

# Verify (rejects self-signed by default)
capiscio badge verify "$TOKEN"

# Accept self-signed for development
capiscio badge verify "$TOKEN" --accept-self-signed
```

> ⚠️ **Production Warning**: Self-signed (Level 0) badges should be rejected in production. Use `--accept-self-signed` only for development/testing.

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
        Mode:             badge.VerifyModeOffline,  // Use trust store
        TrustedIssuers:   []string{"https://registry.capisc.io"},
        Audience:         "https://api.example.com",
        AcceptSelfSigned: false,  // Reject Level 0 in production
    })
    if err != nil {
        var badgeErr *badge.BadgeError
        if errors.As(err, &badgeErr) {
            fmt.Printf("Badge error: %s (code: %s)\n", badgeErr.Message, badgeErr.Code)
        }
    }
    
    fmt.Printf("Trust Level: %d\n", result.Claims.TrustLevel)
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
| `pkg/did` | did:web and did:key parsing and construction |
| `pkg/trust` | Local trust store for CA keys |
| `pkg/revocation` | Revocation list caching |
| `pkg/registry` | Registry interface (Local, Cloud) |
| `pkg/gateway` | HTTP Gateway middleware |
| `pkg/agentcard` | Agent Card schema and validation |
| `pkg/scoring` | Trust scoring engine |
| `pkg/crypto` | JWKS fetching and key utilities |
| `pkg/simpleguard` | Lightweight request signing/verification |

## CLI Reference

For complete command usage and flags, see the [CLI Reference](./reference/cli.md).

## Development

### Prerequisites
- Go 1.21+

### Testing
```bash
go test ./pkg/...
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

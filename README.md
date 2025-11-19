# CapiscIO Core: The Authority Layer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/capiscio/capiscio-core)](https://goreportcard.com/report/github.com/capiscio/capiscio-core)

**CapiscIO Core** is the **Universal Authority Layer** for AI Agents. It provides the infrastructure to Issue, Verify, and Enforce **Trust Badges** (Identity) for any agent, regardless of protocol (REST, MCP, A2A, etc.).

While it serves as the reference implementation for the **Agent-to-Agent (A2A) Protocol**, its primary mission is to secure the broader agent ecosystem.

> **v1.0.0 Release**: This is the first release of CapiscIO Core. It combines the **Validation Engine** (for A2A compliance) with the new **Authority Layer** (for runtime security).

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

*   **Trust Badges**: Issue and Verify VC-aligned JWS tokens (`X-Capiscio-Badge`) that serve as an Agent's passport.
*   **Gateway Sidecar**: A high-performance Reverse Proxy that enforces identity before traffic reaches your Agent.
*   **Registry Interface**: Pluggable trust anchors supporting both **Local Mode** (Air-gapped/Dev) and **Cloud Mode** (Enterprise).
*   **Go-Native**: Built for speed and concurrency, deployable as a single static binary.

## ⚡ Quick Start (The "Minimal Stack")

### 1. Installation

```bash
go install github.com/capiscio/capiscio-core/cmd/capiscio@latest
```

### 2. Issue a Trust Badge (Identity)

You can generate an ephemeral key for testing, or create a persistent key pair for production.

**Option A: Ephemeral (Dev)**
```bash
capiscio badge issue --sub "did:capiscio:agent:my-agent" --exp 1h > badge.jwt 2> key.jwk
```

**Option B: Persistent (Production)**
```bash
# 1. Generate a Key Pair
capiscio key gen --out-priv private.jwk --out-pub public.jwk

# 2. Issue a Badge using the Private Key
capiscio badge issue --key private.jwk --sub "did:capiscio:agent:prod" > badge.jwt
```

**Option C: Automated Renewal (Daemon)**
Run the "Badge Keeper" as a sidecar to keep your badge fresh automatically.
```bash
capiscio badge keep \
  --key private.jwk \
  --sub "did:capiscio:agent:prod" \
  --out badge.jwt \
  --exp 1h \
  --renew-before 10m
```

### 3. Start the Gateway (Enforcement)

Run the gateway as a sidecar to your agent (e.g., running on port 3000). It will block any request without a valid badge.

```bash
# Extract the public key from the previous step
grep "{" key.jwk > public-key.json

# Start the gateway listening on port 8080, forwarding to localhost:3000
capiscio gateway start \
  --port 8080 \
  --target http://localhost:3000 \
  --local-key public-key.json
```

### 4. Make a Request

```bash
# This will succeed (200 OK)
curl -H "X-Capiscio-Badge: $(cat badge.jwt)" http://localhost:8080/api/v1/agent

# This will fail (401 Unauthorized)
curl http://localhost:8080/api/v1/agent
```

## 🌍 Universal Compatibility

While `capiscio-core` is the reference implementation for the **A2A Protocol**, the **Authority Layer** is designed to be **Protocol Agnostic**.

*   **Any Agent**: The Gateway works with any HTTP-based agent (REST, GraphQL, MCP, etc.).
*   **Any Identity**: The Trust Badge is a standard JWT/VC that can wrap any DID.
*   **Any Transport**: Badges are passed via standard HTTP headers (`Authorization` or `X-Capiscio-Badge`).

You can use the **Gateway** to secure *any* AI Agent, even if it doesn't fully implement the A2A Agent Card specification.

## 🏗️ Architecture

### The Authority Layer (New)
*   **Trust Badge**: A standard JWS containing Identity (`sub`) and Capabilities (`vc`).
*   **Gateway**: A reverse proxy that enforces badge validity before forwarding traffic.
*   **Registry**: The source of truth for public keys (Local or Cloud).

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
    
    // 3. Verify a Token
    claims, err := verifier.Verify(context.Background(), tokenString)
    if err != nil {
        log.Fatal("Invalid badge")
    }
    
    fmt.Printf("Authenticated Agent: %s\n", claims.Subject)
}
```

### 2. Validation Engine (Compliance)

```go
import (
    "github.com/capiscio/capiscio-core/pkg/agentcard"
    "github.com/capiscio/capiscio-core/pkg/scoring"
)

func main() {
    // Initialize the engine
    engine := scoring.NewEngine(nil)

    // Load an Agent Card
    card := &agentcard.AgentCard{...}

    // Validate and Score
    result, err := engine.Validate(context.Background(), card, true)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Compliance Score: %.2f\n", result.TrustScore)
}
```

## Development

### Prerequisites
- Go 1.21+

### Testing
```bash
go test ./pkg/...
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

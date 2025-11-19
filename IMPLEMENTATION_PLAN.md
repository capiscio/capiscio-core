# CapiscIO Core Engine - Implementation Plan

This document outlines the roadmap for developing `capiscio-core`, a high-performance Go-based engine that will serve as the single source of truth for the CapiscIO ecosystem. This engine will unify the logic currently duplicated across `capiscio-cli` (TypeScript) and `a2a-security` (Python).

## 🎯 Objectives

1.  **Unification**: Centralize validation, scoring, and security logic.
2.  **Performance**: Leverage Go's concurrency and speed for high-throughput validation.
3.  **Portability**: Enable usage in CLI (native binary), Python (C-shared), and Web/Node (WASM).
4.  **Security**: Provide a robust, auditable cryptographic implementation.

## 🏗️ Architecture

The project will follow a standard Go project layout:

```
capiscio-core/
├── cmd/
│   └── capiscio/           # Main CLI entrypoint (future replacement for Node CLI)
├── pkg/
│   ├── agentcard/          # Domain models and schema validation
│   ├── crypto/             # JWS, JWKS, and signature verification
│   ├── scoring/            # Compliance, Trust, and Availability scoring algorithms
│   ├── protocol/           # A2A protocol clients (JSONRPC, gRPC, REST)
│   └── report/             # Structured validation reporting
├── internal/               # Private implementation details
├── bindings/               # Foreign function interfaces
│   ├── python/             # C-shared library exports for Python
│   └── wasm/               # WebAssembly exports
└── go.mod
```

## 📅 Roadmap

### Phase 1: Foundation & Domain Models
*Goal: Establish the project structure and define the core data structures.*

- [x] **Initialize Module**: Set up `go.mod` and project layout.
- [x] **Agent Card Types**: Define Go structs for `AgentCard`, `AgentProfile`, `Capabilities`, etc., matching the A2A spec.
- [x] **JSON Parsing**: Implement robust JSON unmarshalling with strict type checking.
- [x] **Canonicalization**: Implement canonical JSON generation (RFC 8785 or similar) required for signature verification.

### Phase 2: Cryptography Engine (Critical)
*Goal: Port the JWS/JWKS logic from `capiscio-cli/src/signature-verification.ts`.*

- [x] **JWS Verification**: Implement JWS signature verification (support for `RS256`, `ES256`, `EdDSA`).
- [x] **JWKS Fetching**: Implement secure JWKS fetching with caching and HTTPS enforcement.
- [x] **Detached Signatures**: Support verifying detached JWS signatures as used in Agent Cards.
- [x] **Key Management**: Basic interface for handling trusted keys.

### Phase 3: Validation & Scoring Logic
*Goal: Port the business logic from `capiscio-cli/src/scoring/`.*

- [x] **Schema Validation**: Implement deep validation of Agent Card fields beyond simple types.
- [x] **Compliance Scorer**: Port logic to score adherence to A2A specs.
- [x] **Trust Scorer**: Port logic for calculating trust based on signatures, domain verification, etc.
- [x] **Reporting**: Design a unified `ValidationResult` struct that contains all scores and issues.

### Phase 4: Protocol & Live Testing
*Goal: Implement the "Availability" dimension.*

- [x] **HTTP Client**: Robust HTTP client with timeouts and retries.
- [x] **JSON-RPC Client**: Client to test A2A JSON-RPC endpoints.
- [x] **Availability Scorer**: Logic to ping agents and grade their responsiveness.

### Phase 5: Interfaces & Bindings
*Goal: Make the core usable by other tools.*

- [x] **CLI**: Build the `capiscio` binary command structure (cobra/viper).
- [x] **Python Bindings**: Create a `main.go` in `bindings/python` that exports C-compatible functions.
    - Example: `ValidateAgentCard(json *C.char) *C.char`
- [x] **Integration Test**: Create a proof-of-concept Python script importing the shared library.

### Phase 6: Production Hardening (Current Focus)
*Goal: Prepare the engine for high-traffic, secure production environments.*

- [x] **JWKS Caching**: Implement in-memory cache with TTL to prevent redundant network requests and rate limiting.
- [x] **Engine Configuration**: Introduce `EngineConfig` to allow customization of timeouts, proxies, and behavior.
- [x] **Trust Anchors**: Implement configurable "Trusted Issuers" to allow organizations to define who they trust (replacing hardcoded logic).

## ✅ Status: v1.0.0 Released / v1.1.0 Planning

As of November 18, 2025, the `capiscio-core` engine v1.0.0 is **Production Ready** and released. We are now executing on the "Authority Layer" strategy.

### Key Features (v1.0.0)
*   **High Performance**: Go-based engine with concurrent validation and caching.
*   **Secure**: Robust JWS/JWKS implementation with configurable trust anchors.
*   **Reliable**: Extensive test suite (>80% coverage) covering crypto, scoring, and protocol layers.
*   **Portable**: Ready for CLI (native) and Python (C-shared) integration.

### Phase 7: The Authority Layer (Strategic Pivot)
*Goal: Evolve from "Compliance Validator" to "Identity Authority" and "Anti-Spoofing Shield".*

- [ ] **Delegation Support (OIDC Alignment)**:
    -   Implement validation for OIDC `act` (actor) claims in JWTs (RFC 8693).
    -   **Critical**: Support nested chains (User -> Agent A -> Agent B) for full auditability.
- [ ] **ANS (Agent Name Service) Resolver**:
    -   Implement the IETF draft for Agent Name Service.
    -   **Strategy**: Start with DNS TXT record resolution (e.g., `_agent.name` -> URL) for immediate compatibility.
    -   Add `ResolveANS(name string) (url string, err error)` to the core engine.
- [ ] **Session Integrity (Anti-Smuggling)**:
    -   Design "Gateway Mode" logic to monitor active sessions.
    -   **Performance**: Implement "Heartbeat" or "Sampled" verification for high-throughput streams to avoid latency penalties.
- [ ] **Structured Audit Logging (The "Evidence" Layer)**:
    -   Emit validation events in structured JSON/OTEL format.
    -   Log specific failure reasons (e.g., "Invalid act claim", "ANS lookup failed") for SIEM integration.

### Phase 8: The Enterprise Platform (Open Core Architecture)
*Goal: Establish the commercial "Moat" by separating Execution (Open Source) from Control (Proprietary).*

- [ ] **Architectural Separation**:
    -   **CapiscIO Gateway (Open Source)**: The Go-based sidecar/proxy. Handles traffic interception, policy enforcement, and validation.
    -   **CapiscIO Control Plane (Proprietary SaaS)**: The centralized API for Policy Management, Audit Log Ingestion, and Analytics.
- [ ] **Data Contract Implementation**:
    -   **Policy Fetch**: Gateway pulls configuration/rules from the Control Plane via authenticated API.
    -   **Audit Ingest**: Gateway pushes structured logs to the Control Plane for storage and SIEM export.

### Next Steps
1.  **Immediate**: Integrate `capiscio-core` into `capiscio-cli` and `a2a-security`.
2.  **Q1 2026**: Build the "CapiscIO Gateway" (Reverse Proxy) using the core engine.
3.  **Q1 2026**: Release the ANS Resolver reference implementation.
4.  **Q2 2026**: Launch CapiscIO Control Plane (SaaS) Beta.

## 🛠️ Technical Decisions

- **JSON Library**: Use standard `encoding/json` or `goccy/go-json` for performance if needed.
- **Crypto Library**: Use `github.com/go-jose/go-jose/v4` for robust JWS/JWKS support.
- **CLI Framework**: `github.com/spf13/cobra` for the CLI structure.
- **Testing**: Native Go testing + `testify` for assertions.

## 🚀 Getting Started

1.  Initialize the Go module.
2.  Create the `AgentCard` struct definition.
3.  Implement the `VerifySignature` function.

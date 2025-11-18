# CapiscIO Core

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/capiscio/capiscio-core)](https://goreportcard.com/report/github.com/capiscio/capiscio-core)

The core engine for the CapiscIO ecosystem, written in Go. This library provides the central logic for Agent Card validation, scoring, and cryptographic verification.

**CapiscIO Core** serves as a reference implementation and validator for the **Agent-to-Agent (A2A) Protocol**, a project of the **Linux Foundation**.

Learn more about the CapiscIO ecosystem at [capisc.io](https://capisc.io).

## Overview

`capiscio-core` is designed to be the single source of truth for:
- **Agent Card Validation**: Ensuring compliance with the A2A protocol.
- **Trust Scoring**: Calculating trust scores based on signatures and other factors.
- **Cryptography**: Handling JWS signature verification and JWKS management.
- **Availability Testing**: Checking agent endpoints for responsiveness.

## Usage

### As a Go Library

```bash
go get github.com/capiscio/capiscio-core
```

```go
import (
    "context"
    "github.com/capiscio/capiscio-core/pkg/agentcard"
    "github.com/capiscio/capiscio-core/pkg/scoring"
)

func main() {
    // Initialize the engine with default configuration
    engine := scoring.NewEngine(nil)

    // Load your Agent Card
    card := &agentcard.AgentCard{...}

    // Validate
    result, err := engine.Validate(context.Background(), card, true)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Trust Score: %.2f\n", result.TrustScore)
}
```

### As a CLI

Download the latest release from the [Releases](https://github.com/capiscio/capiscio-core/releases) page.

```bash
# Validate a local file
./capiscio validate ./agent-card.json

# Validate a remote URL with live availability check
./capiscio validate https://example.com/agent-card.json --live
```

### As a Python Library

The core engine can be compiled as a shared library for use in Python.

```bash
# Build the shared library
go build -buildmode=c-shared -o capiscio_core.so ./bindings/python/main.go
```

(Python package coming soon to PyPI)

## Development

### Prerequisites

- Go 1.21+

### Building

```bash
make build
```

### Testing

```bash
go test -cover ./...
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

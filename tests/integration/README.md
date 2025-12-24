# capiscio-core Integration Tests

This directory contains integration tests that verify capiscio-core CLI functionality against a live capiscio-server instance.

## Architecture

- **capiscio-core (CLI)**: System under test - validates badges, manages keys, interacts with server
- **capiscio-server**: Live HTTP API server with PostgreSQL backend
- **docker-compose.yml**: Orchestrates all services for testing

## Running Tests

### Prerequisites

1. Build the capiscio-core binary:
   ```bash
   cd /Users/beondenood/Development/CapiscIO/capiscio-core
   make build-cli
   ```

2. Build the capiscio-server binary:
   ```bash
   cd /Users/beondenood/Development/CapiscIO/capiscio-server
   make build
   ```

### Run with Docker Compose

```bash
cd tests/integration
docker-compose up --build --abort-on-container-exit
```

### Run locally (without Docker)

1. Start capiscio-server and database:
   ```bash
   cd /Users/beondenood/Development/CapiscIO/capiscio-server
   docker-compose up -d
   ```

2. Run integration tests:
   ```bash
   cd /path/to/capiscio-core
   export API_BASE_URL=http://localhost:8080
   go test -v ./tests/integration/...
   ```

## Test Coverage

These integration tests verify:

- [ ] Badge issuance via server API
- [ ] Badge verification against live JWKS
- [ ] Proof of Possession (PoP) challenge flow
- [ ] DV order creation and finalization
- [ ] DV grant status checking
- [ ] DV grant revocation
- [ ] Error handling and edge cases

## Environment Variables

- `API_BASE_URL`: Base URL for capiscio-server (default: `http://localhost:8080`)
- `DATABASE_URL`: PostgreSQL connection string (used by server)
- `CA_PRIVATE_KEY_JWK`: JWK for badge signing (used by server)

## CI/CD Integration

In GitHub Actions, use:

```yaml
- name: Run integration tests
  run: |
    cd capiscio-core/tests/integration
    docker-compose up --build --abort-on-container-exit --exit-code-from test-runner
```

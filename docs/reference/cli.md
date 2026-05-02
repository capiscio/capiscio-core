# CLI Reference

This reference documents the commands available in the `capiscio` core binary.

## Global Flags

- `-v, --version`: Show version information.
- `-h, --help`: Show help message.

## Commands

### `validate`

Validates an Agent Card from a local file or URL. Checks compliance, verifies signatures, and optionally tests availability.

```bash
capiscio validate [file-or-url] [flags]
```

**Options:**
- `--strict`: Enable strict validation mode.
- `--test-live`: Test live agent endpoint.
- `--skip-signature`: Skip JWS signature verification.
- `--schema-only`: Validate schema only, skip endpoint testing.
- `--registry-ready`: Check registry deployment readiness.
- `--errors-only`: Show only errors and warnings.
- `--json`: Output results as JSON.
- `--timeout <duration>`: Request timeout (default 10s).

**Examples:**
```bash
# Validate local file
capiscio validate ./agent-card.json

# Validate with JSON output
capiscio validate ./agent-card.json --json

# Validate URL with live testing
capiscio validate https://example.com/.well-known/agent-card.json --test-live
```

---

### `badge`

Manage Trust Badges for CapiscIO agents. Trust Badges are signed JWS tokens that provide portable, verifiable identity for agents. See RFC-002 for the full specification.

#### `badge issue`

Issue a new Trust Badge.

```bash
capiscio badge issue [flags]
```

**Options:**
- `--self-sign`: Self-sign for development (explicit, implies level 0).
- `--sub <did>`: Subject DID (did:web format).
- `--level <0-4>`: Trust level: 0 (SS), 1 (REG), 2 (DV), 3 (OV), 4 (EV) per RFC-002 (default "1").
- `--exp <duration>`: Expiration duration (default 5m per RFC-002).
- `--key <path>`: Path to private key file (optional).
- `--domain <string>`: Agent domain.
- `--iss <did>`: Issuer DID (default "did:web:registry.capisc.io").
- `--aud <urls>`: Audience (comma-separated URLs).

**Examples:**
```bash
# Self-signed badge for development (Level 0)
capiscio badge issue --self-sign --sub did:web:example.com:agents:my-agent

# CA-issued badge with specific trust level (Level 2 - OV)
capiscio badge issue --key ca-private.jwk --level 2 --domain example.com

# With audience restriction
capiscio badge issue --self-sign --aud "https://api.example.com,https://backup.example.com"
```

#### `badge verify`

Verify a Trust Badge and display the claims.

```bash
capiscio badge verify [token] [flags]
```

**Options:**
- `--key <path>`: Path to public key file (JWK).
- `--offline`: Offline mode (uses trust store).
- `--audience <url>`: Expected audience claim value (verifies the badge is intended for this URL).
- `--skip-revocation`: Skip revocation check (testing only).
- `--skip-agent-status`: Skip agent status check (testing only).
- `--trusted-issuers <urls>`: Comma-separated list of trusted issuer URLs.
- `--accept-self-signed`: Accept Level 0 self-signed badges with did:key issuers (development/testing only).

**Examples:**
```bash
# Online verification with local key
capiscio badge verify $TOKEN --key ca-public.jwk

# Offline verification
capiscio badge verify $TOKEN --offline

# With audience check
capiscio badge verify $TOKEN --key ca-public.jwk --audience https://api.example.com

# Accept self-signed Level 0 badges (development only)
capiscio badge verify $TOKEN --accept-self-signed
```

#### `badge keep`

Run a daemon that automatically renews badges before they expire.

```bash
capiscio badge keep [flags]
```

**Options:**
- `--agent-id <uuid>`: Agent ID (UUID) to request badges for (CA mode).
- `--api-key <string>`: API key for CA authentication (or use `CAPISCIO_API_KEY` env).
- `--ca <url>`: CA URL for badge requests (default "https://registry.capisc.io").
- `--check-interval <duration>`: Interval to check for renewal (default 30s).
- `--domain <string>`: Agent domain (optional).
- `--exp <duration>`: Expiration duration (default 5m).
- `--key <path>`: Path to private key file (required for `--self-sign`).
- `--level <0-4>`: Trust level: 0 (SS), 1 (REG), 2 (DV), 3 (OV), 4 (EV) per RFC-002 (default "1").
- `--out <path>`: Output file path (default "badge.jwt").
- `--renew-before <duration>`: Time before expiry to renew (default 1m).
- `--self-sign`: Self-sign badges locally (development only).

**Examples:**
```bash
# CA mode - production use
capiscio badge keep --agent-id <uuid> --api-key $CAPISCIO_API_KEY --out badge.jwt

# Self-signed mode for development
capiscio badge keep --self-sign --key private.jwk --out badge.jwt
```

#### `badge request`

Request a Trust Badge from a CA using the Proof of Possession (PoP) protocol (RFC-003). Performs a 2-phase challenge-response flow.

```bash
capiscio badge request [flags]
```

**Options:**
- `--did <did>`: Agent DID (did:web or did:key).
- `--key <path>`: Path to private key file (JWK format).
- `--ca <url>`: CA URL for PoP flow (default "https://registry.capisc.io").
- `--api-key <string>`: API key for CA authentication (or use `CAPISCIO_API_KEY` env).
- `--audience <urls>`: Comma-separated list of audiences.
- `--out <path>`: Output file path for badge (optional).
- `--ttl <seconds>`: Badge TTL in seconds (default 300).

**Examples:**
```bash
capiscio badge request \
  --did did:web:example.com:agents:my-agent \
  --key ./agent-key.jwk \
  --api-key $CAPISCIO_API_KEY \
  --out badge.jwt
```

#### `badge dv`

Manage Domain Validated (DV) badge orders using the ACME-Lite protocol. DV badges provide cryptographic proof of domain ownership (Trust Level 2).

```bash
capiscio badge dv [command]
```

**Subcommands:**
- `create`: Create a DV badge order.
- `status`: Check DV order status.
- `finalize`: Finalize DV order and receive grant.

**Examples:**
```bash
# Create HTTP-01 challenge order
capiscio badge dv create --domain example.com --challenge-type http-01 --key agent.jwk

# Check order status
capiscio badge dv status --order-id <uuid>

# Finalize order after provisioning challenge
capiscio badge dv finalize --order-id <uuid> --out grant.jwt
```

---

### `init`

Initialize a new CapiscIO agent identity. This is the "Let's Encrypt" style setup for agents - one command does everything: generates keys, derives a DID, registers with the server, and creates an agent card.

```bash
capiscio init [flags]
```

**Options:**
- `--api-key <string>`: CapiscIO API key (prefer `CAPISCIO_API_KEY` env var for security).
- `--agent-id <uuid>`: Agent ID (UUID). If omitted, will use first agent from registry.
- `--name <string>`: Agent name (for display purposes).
- `--server <url>`: CapiscIO registry server URL (default "https://registry.capisc.io").
- `--output <path>`: Output directory (default "~/.capiscio/keys/{agent-id}/").
- `--auto-badge`: Automatically request initial Trust Badge (default false, use `badge keep` instead).
- `--force`: Overwrite existing keys (use with caution!).

**Output Files:**
- `private.jwk` - Ed25519 private key (0600 permissions - keep secret!)
- `public.jwk` - Ed25519 public key
- `did.txt` - The agent's did:key identifier
- `agent-card.json` - A2A-compliant agent card with x-capiscio extension

**Examples:**
```bash
# Initialize using environment variable (recommended)
export CAPISCIO_API_KEY=sk_live_...
capiscio init --agent-id my-agent-001

# Initialize with specific agent name
capiscio init --agent-id my-agent-001 --name "My Research Agent"

# Initialize with custom output directory
capiscio init --agent-id my-agent-001 --output ./my-agent-keys/

# Re-initialize (overwrite existing keys - use with caution!)
capiscio init --agent-id my-agent-001 --force
```

**Security Notes:**
- The API key can be provided via the `CAPISCIO_API_KEY` environment variable (recommended) or the `--api-key` flag. The environment variable is preferred as CLI arguments are visible in process listings.
- Private keys are created with 0600 permissions (owner read/write only).
- Always keep your `private.jwk` secret and backed up.
- Using `--force` will invalidate any existing badges signed with the previous key.

---

### `key`

Manage cryptographic keys.

#### `key gen`

Generate a new Ed25519 key pair.

```bash
capiscio key gen [flags]
```

**Options:**
- `--out-priv <path>`: Output path for private key (default "private.jwk").
- `--out-pub <path>`: Output path for public key (default "public.jwk").

**Examples:**
```bash
capiscio key gen --out-priv private.jwk --out-pub public.jwk
```

---

### `trust`

Manage the local trust store for offline badge verification. The trust store contains CA public keys that are trusted for badge verification, enabling offline and air-gapped deployments.

**Location:** `~/.capiscio/trust/` (or `$CAPISCIO_TRUST_PATH`)

#### `trust add`

Add a CA public key to the trust store.

```bash
capiscio trust add [jwk-file] [flags]
```

**Options:**
- `--from-jwks <url>`: Fetch from JWKS URL or '-' for stdin.

**Examples:**
```bash
# Add from a JWK file
capiscio trust add ca-public.jwk

# Add from JWKS URL (production CA)
capiscio trust add --from-jwks https://registry.capisc.io/.well-known/jwks.json

# Add from stdin (pipe from curl)
curl -s https://registry.capisc.io/.well-known/jwks.json | capiscio trust add --from-jwks -
```

#### `trust list`

List trusted CA keys.

```bash
capiscio trust list
```

#### `trust remove`

Remove a CA key from the trust store.

```bash
capiscio trust remove [key-id]
```

---

### `gateway`

Start the CapiscIO Gateway.

#### `gateway start`

Start the gateway server as a reverse proxy that enforces badge validity.

```bash
capiscio gateway start [flags]
```

**Options:**
- `--port <number>`: Port to listen on (default 8080).
- `--target <url>`: Upstream target URL (default "http://localhost:3000").
- `--local-key <path>`: Path to local public key file (JWK).
- `--registry-url <url>`: URL of the CapiscIO Registry.

**Examples:**
```bash
# Start gateway with local key verification
capiscio gateway start --port 8080 --target http://localhost:3000 --local-key public-key.jwk

# Start gateway with registry
capiscio gateway start --port 8080 --target http://localhost:3000 --registry-url https://registry.capisc.io
```

---

### `envelope`

Manage Authority Envelopes for delegated capability authorization (RFC-008). Authority Envelopes are signed JWS tokens that grant capabilities to agents and can be delegated through chains with monotonically narrowing permissions.

#### `envelope issue`

Issue a root Authority Envelope.

```bash
capiscio envelope issue [flags]
```

**Options:**
- `--subject <did>`: Subject DID (required).
- `--capability <string>`: Capability class (e.g. `tools.database.read`).
- `--depth <int>`: Maximum delegation depth remaining.
- `--key <path>`: Path to issuer private key file (JWK).
- `--issuer <did>`: Issuer DID (auto-derived from key if not set).
- `--expiry <duration>`: Envelope expiry duration (default 1h).
- `--min-mode <string>`: Minimum enforcement mode (`EM-OBSERVE`|`EM-GUARD`|`EM-DELEGATE`|`EM-STRICT`).
- `--constraints <json>`: Constraints as JSON object.
- `--badge-jti <string>`: Issuer badge JTI.
- `--txn-id <string>`: Transaction ID (auto-generated if not set).

**Examples:**
```bash
capiscio envelope issue --subject did:key:z6Mk... --capability tools.database --depth 5
capiscio envelope issue --key issuer.jwk --subject did:key:z6Mk... --capability tools.database.read --depth 3
```

#### `envelope derive`

Derive a child envelope from a parent. The child must have narrower or equal permissions across all dimensions.

```bash
capiscio envelope derive [flags]
```

**Options:**
- `--parent <path>`: Path to parent envelope file (required).
- `--subject <did>`: Subject DID (required).
- `--capability <string>`: Capability class (must be within parent scope).
- `--depth <int>`: Delegation depth remaining (must be less than parent).
- `--key <path>`: Path to issuer private key file (JWK).
- `--expiry <duration>`: Envelope expiry duration (default 30m).
- `--min-mode <string>`: Minimum enforcement mode.
- `--constraints <json>`: Constraints as JSON object.

**Examples:**
```bash
capiscio envelope derive --parent root.env --key child.jwk --subject did:key:z6Mk... --capability tools.database.read --depth 2
```

#### `envelope verify`

Verify an Authority Envelope's signature, temporal validity, and structure.

```bash
capiscio envelope verify [envelope-file] [flags]
```

**Options:**
- `--min-mode <string>`: Required minimum enforcement mode.
- `--skip-badge`: Skip badge verification (testing only).

#### `envelope inspect`

Parse and display the contents of an Authority Envelope without signature verification.

```bash
capiscio envelope inspect [envelope-file]
```

#### `envelope chain`

Verify a delegation chain of Authority Envelopes (root-to-leaf order). Validates hash links, DID continuity, narrowing rules, and signatures.

```bash
capiscio envelope chain [envelope-files...] [flags]
```

**Options:**
- `--skip-badge`: Skip badge verification (testing only).

**Examples:**
```bash
capiscio envelope chain root.env child1.env child2.env
```

---

### `policy`

Manage CapiscIO YAML policy configuration files.

#### `policy validate`

Validate a YAML policy config file locally. Checks schema version, trust levels, DID formats, rate limits, operation patterns, and MCP tool rules.

```bash
capiscio policy validate [flags]
```

**Options:**
- `-f, --file <path>`: Path to YAML policy config file (default "capiscio-policy.yaml").
- `--json`: Output parsed config as JSON on success.

**Examples:**
```bash
capiscio policy validate
capiscio policy validate -f my-policy.yaml --json
```

#### `policy context`

Fetch the aggregate policy context from the CapiscIO registry.

```bash
capiscio policy context [flags]
```

**Options:**
- `--api-key <string>`: CapiscIO API key (prefer `CAPISCIO_API_KEY` env var).
- `-o, --output <path>`: Output file path (default: stdout).
- `--registry <url>`: CapiscIO registry server URL (default "https://registry.capisc.io").

**Examples:**
```bash
export CAPISCIO_API_KEY=sk_live_...
capiscio policy context
capiscio policy context -o policy-context.json
```

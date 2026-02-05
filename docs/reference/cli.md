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
- `--level <0-4>`: Trust level: 0 (self-signed), 1 (DV), 2 (OV), 3 (EV), 4 (CV) (default "1").
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
- `--self-sign`: Self-sign instead of requesting from CA.
- `--key <path>`: Path to private key file (required for self-sign).
- `--sub <did>`: Subject DID.
- `--out <path>`: Output file path (default "badge.jwt").
- `--exp <duration>`: Expiration duration (default 5m).
- `--renew-before <duration>`: Time before expiry to renew (default 1m).
- `--check-interval <duration>`: Interval to check for renewal (default 30s).
- `--ca <url>`: CA URL for badge requests (future).
- `--api-key <string>`: API key for CA authentication (future).
- `--domain <string>`: Agent domain.
- `--iss <did>`: Issuer DID (e.g. `did:web:registry.capisc.io`).
- `--level <0-4>`: Trust level (0=self-signed, 1=DV, 2=OV, 3=EV, 4=CV; default "1").

**Examples:**
```bash
# Self-signed mode for development
capiscio badge keep --self-sign --key private.jwk --out badge.jwt

# With CA (future)
capiscio badge keep --ca https://registry.capisc.io --api-key $API_KEY
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

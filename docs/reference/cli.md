# CLI Reference

This reference documents the commands available in the `capiscio` core binary.

## Global Flags

- `--version`: Show version information.
- `--help`: Show help message.
- `--json`: Output results in JSON format.

## Commands

### `validate`

Validates an Agent Card.

```bash
capiscio validate <path-to-card>
```

**Options:**
- `--strict`: Enable strict validation mode.
- `--test-live`: Perform live endpoint testing.
- `--skip-signature`: Skip JWS signature verification.
- `--schema-only`: Validate schema only, skip endpoint testing.
- `--errors-only`: Show only errors and warnings.
- `--timeout`: Request timeout (default 10s).

### `score`

Calculates the score for an Agent Card without full validation report.

```bash
capiscio score <path-to-card>
```

**Options:**
- `--json`: Output the score in JSON format.

**Output:**
By default, prints the score as a numeric value to stdout. If `--json` is specified, outputs a JSON object containing the score.

### `badge issue`

Issues a badge to an agent.

```bash
capiscio badge issue [options]
```

**Options:**
- `--sub <did>`: Subject DID (e.g., `did:capiscio:agent:my-agent`).
- `--exp <duration>`: Expiration duration (e.g., `1h`).
- `--key <path>`: Path to private key JWK.

### `badge keep`

Keeps (renews or maintains) a badge for an agent.

```bash
capiscio badge keep [options]
```

**Options:**
- `--key <path>`: Path to private key JWK.
- `--sub <did>`: Subject DID.
- `--out <path>`: Output path for the badge.
- `--exp <duration>`: Expiration duration.
- `--renew-before <duration>`: Renew badge if it expires within this duration.

### `key gen`

Generates a new cryptographic key pair.

```bash
capiscio key gen [options]
```

**Options:**
- `--out-priv <path>`: Output path for private key.
- `--out-pub <path>`: Output path for public key.

### `gateway start`

Starts the Capiscio gateway service.

```bash
capiscio gateway start [options]
```

**Options:**
- `--port <number>`: Port to listen on.
- `--target <url>`: Target URL to forward requests to.
- `--local-key <path>`: Path to public key for local verification.

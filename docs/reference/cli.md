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
- `--live`: Perform live endpoint testing.

### `score`

Calculates the score for an Agent Card without full validation report.

```bash
capiscio score <path-to-card>
```

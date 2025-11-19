# v1.0.1: The Minimal Authority Stack

**CapiscIO Core** is the Universal Authority Layer for AI Agents—providing Identity, Verification, and Enforcement without the complexity of cloud IAM.

## 🚀 New in v1.0.1
*   **Automated Renewal**: New `capiscio badge keep` daemon for "set-and-forget" identity management.
*   **Offline Verification**: Trust Badges now embed public keys (`jwk`), allowing the Gateway to verify signatures without external lookups.
*   **Persistent Identity**: New `capiscio key gen` command for production key management.
*   **Gateway Sidecar**: Zero-code reverse proxy that enforces `X-Capiscio-Badge` authorization.

## 📦 Get Started

```bash
go install github.com/capiscio/capiscio-core/cmd/capiscio@v1.0.1
```

**Quick Setup:**
```bash
# 1. Generate Keys
capiscio key gen --out-priv private.jwk --out-pub public.jwk

# 2. Start Auto-Renewal Daemon
capiscio badge keep --key private.jwk --sub "did:capiscio:prod" &

# 3. Start Enforcement Gateway
capiscio gateway start --port 8080 --target http://localhost:3000 --local-key public.jwk
```

# Verification Locality Audit

**Created:** 2026-05-26  
**Phase:** 0.1  
**Status:** 🔄 In Progress  
**RFC Reference:** RFC-001 §2.3 (Verification Locality Principle)

---

## Executive Summary

This audit documents all synchronous server dependencies in `capiscio-core` trust evaluation paths. The goal is to identify every location where runtime verification blocks on network calls, enabling the refactoring required for local-first verification.

**Critical Finding:** The current architecture has **7 synchronous server call sites** in the verification critical path. These must be eliminated or made optional for RFC-001 §2.3 compliance.

---

## Audit Scope

| Component | File | Audited | Risk Level |
|-----------|------|---------|------------|
| Badge verification | `pkg/badge/verifier.go` | ✅ | 🔴 HIGH |
| Envelope verification | `pkg/envelope/verifier.go` | ✅ | 🟡 MEDIUM |
| Chain verification | `pkg/envelope/chain.go` | ✅ | 🟢 LOW |
| DID resolution | `pkg/did/web_resolver.go` | ✅ | 🔴 HIGH |
| Registry client | `pkg/registry/cloud.go` | ✅ | 🔴 HIGH |
| Local registry | `pkg/registry/local.go` | ✅ | 🟢 LOW |
| Gateway middleware | `pkg/gateway/middleware.go` | ✅ | 🔴 HIGH |

---

## Component: pkg/badge/verifier.go

### Current Behavior

The `Verifier` struct holds a `registry.Registry` interface and uses it for:
1. Public key resolution (JWKS fetch)
2. Badge revocation checks
3. Agent status checks

```go
type Verifier struct {
    registry registry.Registry
}

func NewVerifier(reg registry.Registry) *Verifier {
    return &Verifier{registry: reg}
}
```

### Server Dependencies

| Dependency | Method | Sync Call | Notes |
|------------|--------|-----------|-------|
| JWKS fetch | `getPublicKey()` | ✅ YES | Calls `v.registry.GetPublicKey(ctx, issuer)` |
| Revocation check | `checkRevocationOnline()` | ✅ YES | Calls `v.registry.GetBadgeStatus(ctx, issuer, jti)` |
| Agent status | `checkAgentStatus()` | ✅ YES | Calls `v.registry.GetAgentStatus(ctx, issuer, agentID)` |

### Analysis

**Line 157-163 — `getPublicKey()`:**
```go
func (v *Verifier) getPublicKey(ctx context.Context, issuerDID *did.DID, isSelfSigned bool, issuer string) (crypto.PublicKey, error) {
    if isSelfSigned {
        return issuerDID.GetPublicKey(), nil
    }
    // Fetch CA public key from registry — SYNCHRONOUS SERVER CALL
    pubKey, err := v.registry.GetPublicKey(ctx, issuer)
    ...
}
```

**Line 475-481 — `checkRevocationOnline()`:**
```go
func (v *Verifier) checkRevocationOnline(ctx context.Context, claims *Claims) error {
    status, err := v.registry.GetBadgeStatus(ctx, claims.Issuer, claims.JTI)
    // SYNCHRONOUS SERVER CALL
    ...
}
```

### Verification Locality After Changes

- [ ] Can verify badge without synchronous server call: **NO** (requires refactoring)
- [ ] Can verify envelope without synchronous server call: **NO** (depends on badge verifier)
- [ ] Can check revocation against local cache: **PARTIAL** (only in `VerifyModeOffline`)

### Required Changes

1. **Add `VerifyWithMaterial()` variant** that accepts pre-loaded `TrustMaterial`
2. **Add `NewVerifierWithTrustMaterial()` constructor** that doesn't require `Registry`
3. **Make `RevocationCache` a first-class component**, not just an option
4. **Deprecate** `NewVerifier(reg)` over 1-2 releases
5. **Add locality invariant test** that fails if HTTP calls occur

---

## Component: pkg/envelope/verifier.go

### Current Behavior

The envelope `Verifier` wraps a `badge.Verifier` and uses a `KeyResolver` function for DID-to-key resolution.

```go
type Verifier struct {
    BadgeVerifier *badge.Verifier
    KeyResolver   KeyResolver
}
```

### Server Dependencies

| Dependency | Method | Sync Call | Notes |
|------------|--------|-----------|-------|
| Badge verification | `verifyBadge()` | ✅ YES | Delegates to `badge.Verifier` — inherits all issues |
| DID resolution | `resolveAndVerifySignature()` | ⚠️ CONDITIONAL | If `KeyResolver` uses `WebResolver`, it's sync |

### Analysis

**Line 35-48 — `NewCompositeKeyResolver()`:**
```go
func NewCompositeKeyResolver(webResolver *did.WebResolver) KeyResolver {
    return func(ctx context.Context, didStr string, kid string) (crypto.PublicKey, error) {
        parsed, err := did.Parse(didStr)
        ...
        if parsed.IsKeyDID() {
            return DefaultKeyResolver(ctx, didStr, kid)  // LOCAL — no network
        }
        if webResolver == nil {
            return nil, fmt.Errorf("did:web resolution requires a WebResolver...")
        }
        return webResolver.Resolve(ctx, didStr, kid)  // SYNCHRONOUS HTTP CALL
    }
}
```

### Verification Locality After Changes

- [ ] Can verify envelope without synchronous server call: **NO** (badge verifier dependency)
- [ ] Can resolve did:key locally: **YES** (`DefaultKeyResolver` is local)
- [ ] Can resolve did:web locally: **NO** (requires HTTP fetch)

### Required Changes

1. **Accept `TrustMaterial` at construction**, not just `badge.Verifier`
2. **Add `WithCachedDIDDocument()` option** for pre-resolved DID material
3. **Ensure KeyResolver can use cached DID documents**

---

## Component: pkg/envelope/chain.go

### Current Behavior

Chain verification (`ValidateChainIntegrity()`) is **purely structural** — it validates:
- Hash links
- DID continuity  
- Narrowing rules
- TxnID consistency

### Server Dependencies

| Dependency | Sync Call | Notes |
|------------|-----------|-------|
| None | ❌ NO | Chain validation is local-only |

### Analysis

`ValidateChainIntegrity()` operates on `Chain []*Token` — already-parsed envelope tokens. **No network calls.**

### Verification Locality After Changes

- [x] Can validate chain without synchronous server call: **YES** ✅

### Required Changes

**None.** Chain validation is already local-first compliant.

---

## Component: pkg/did/web_resolver.go

### Current Behavior

⚠️ **COMPLEXITY BOMB** ⚠️

The `WebResolver` fetches DID documents over HTTPS for `did:web` identifiers.

```go
func (r *WebResolver) Resolve(ctx context.Context, didStr string, kid string) (crypto.PublicKey, error) {
    ...
    doc, err := r.resolveDocument(ctx, docURL)  // SYNCHRONOUS HTTP CALL
    ...
}
```

### Server Dependencies

| Dependency | Method | Sync Call | Notes |
|------------|--------|-----------|-------|
| DID document fetch | `resolveDocument()` | ✅ YES | HTTP GET to `did:web` URL |

### Analysis

**Line 78-87 — `Resolve()`:**
- Checks cache first (good)
- On cache miss → **synchronous HTTP fetch** (bad for locality)
- 5-minute cache TTL by default
- Has SSRF protections (good)

**Fundamental issue:** `did:web` is **inherently remote**. Unlike `did:key` (self-contained), `did:web:example.com` requires fetching `https://example.com/.well-known/did.json`.

### Verification Locality After Changes

- [ ] Can resolve did:web without synchronous server call: **NO** (without pre-cached material)
- [x] Can resolve did:web from cache: **YES** (if already cached)

### Required Changes

1. **Add `LoadFromFile()` method** — load DID documents from exported trust bundle
2. **Add `Export()` method** — persist resolved documents to file
3. **Add deterministic cache-miss policy**: fail-closed vs stale-trust
4. **DID document snapshot at issuance** — issuer should capture and sign DID state
5. **Consider signed DID caching** for high-assurance deployments

---

## Component: pkg/registry/cloud.go

### Current Behavior

`CloudRegistry` implements `Registry` interface with HTTP calls to the registry server.

### Server Dependencies

| Dependency | Method | Sync Call | Notes |
|------------|--------|-----------|-------|
| JWKS fetch | `GetPublicKey()` | ✅ YES | HTTP GET to `/.well-known/jwks.json` |
| Badge status | `GetBadgeStatus()` | ✅ YES | HTTP GET to `/v1/badges/{jti}/status` |
| Agent status | `GetAgentStatus()` | ✅ YES | HTTP GET to `/v1/agents/{id}/status` |
| Revocation sync | `SyncRevocations()` | ✅ YES | HTTP GET to `/v1/revocations?since=...` |

### Analysis

**Line 38-54 — `GetPublicKey()`:**
```go
func (r *CloudRegistry) GetPublicKey(ctx context.Context, issuer string) (crypto.PublicKey, error) {
    // Check cache (5 min TTL)
    r.mu.RLock()
    key, ok := r.cache[issuer]
    ...
    if ok && time.Now().Before(expiry) {
        return key, nil
    }
    ...
    // SYNCHRONOUS HTTP FETCH on cache miss
    resp, err := r.Client.Do(req)
    ...
}
```

This is a **major violation** of RFC-001 §2.3. Every cache miss blocks verification on HTTP.

### Verification Locality After Changes

- [ ] Can provide public keys without synchronous call: **NO** (cache miss blocks)
- [ ] Can check revocation without synchronous call: **NO** (always calls server)

### Required Changes

1. **This interface must evolve to issuance/distribution-oriented**
2. **Create new `TrustMaterialProvider` interface** for local-first verification
3. **Add `WarmupAsync()` method** for pre-fetching at startup
4. **Make `SyncRevocations()` the primary revocation path** (batch, not per-verification)

---

## Component: pkg/registry/local.go

### Current Behavior

`LocalRegistry` reads public key from a local JWK file. **No HTTP calls.**

### Server Dependencies

| Dependency | Method | Sync Call | Notes |
|------------|--------|-----------|-------|
| Key read | `GetPublicKey()` | ❌ NO | Reads from filesystem |
| Badge status | `GetBadgeStatus()` | ❌ N/A | Returns error (not supported) |
| Agent status | `GetAgentStatus()` | ❌ N/A | Returns error (not supported) |

### Analysis

`LocalRegistry` is conceptually correct for local-first verification, but:
- Only supports a single key file (not multi-issuer)
- Returns errors for status checks instead of using cache
- No revocation cache support

### Verification Locality After Changes

- [x] Can provide public keys without synchronous call: **YES** ✅
- [ ] Can check revocation without synchronous call: **NO** (not implemented)

### Required Changes

1. **Support multiple issuer keys** (keyed by issuer DID)
2. **Add revocation cache loading** from local file
3. **Change status methods** to use local cache, not error

---

## Component: pkg/gateway/middleware.go

### Current Behavior

Gateway middleware takes a `*badge.Verifier` and calls `verifier.Verify()` synchronously in the HTTP request path.

```go
func NewPolicyMiddleware(verifier *badge.Verifier, config PEPConfig, next http.Handler, callbacks ...PolicyEventCallback) http.Handler {
    ...
}

func (p *pep) serveHTTP(w http.ResponseWriter, r *http.Request) {
    ...
    claims, err := p.verifier.Verify(r.Context(), token)  // BLOCKS ON REGISTRY
    ...
}
```

### Server Dependencies

| Dependency | Method | Sync Call | Notes |
|------------|--------|-----------|-------|
| Badge verification | `serveHTTP()` | ✅ YES | Inherits all `badge.Verifier` issues |
| Chain verification | `verifyAuthorityChain()` | ⚠️ CONDITIONAL | If envelope verification enabled |

### Analysis

**Line 120-128 — `serveHTTP()`:**
```go
claims, err := p.verifier.Verify(r.Context(), token)
if err != nil {
    p.logger.WarnContext(r.Context(), "badge verification failed", ...)
    http.Error(w, "Invalid Trust Badge", http.StatusUnauthorized)
    return
}
```

Every HTTP request through the gateway **blocks on the badge verifier**, which may block on the registry.

### Verification Locality After Changes

- [ ] Can verify requests without synchronous server call: **NO** (inherits verifier issues)

### Required Changes

1. **Gateway must accept `TrustMaterial` injection**, not own its lifecycle
2. **Ensure verifier uses local-first verification**
3. **Document that gateway MUST be bootstrapped with trust material**

---

## Synchronous Call Site Summary

| Location | Method | Call Type | Blocking? |
|----------|--------|-----------|-----------|
| `pkg/badge/verifier.go:160` | `getPublicKey()` | `registry.GetPublicKey()` | ✅ YES |
| `pkg/badge/verifier.go:476` | `checkRevocationOnline()` | `registry.GetBadgeStatus()` | ✅ YES |
| `pkg/badge/verifier.go:507` | `checkAgentStatus()` | `registry.GetAgentStatus()` | ✅ YES |
| `pkg/did/web_resolver.go:133` | `resolveDocument()` | HTTP GET | ✅ YES |
| `pkg/registry/cloud.go:58` | `GetPublicKey()` | HTTP GET | ✅ YES |
| `pkg/registry/cloud.go:113` | `GetBadgeStatus()` | HTTP GET | ✅ YES |
| `pkg/registry/cloud.go:140` | `GetAgentStatus()` | HTTP GET | ✅ YES |

**Total: 7 synchronous call sites to eliminate/make optional.**

---

## Verification Locality Invariants (RFC-001 §2.3)

Per the implementation plan decisions, these invariants must be **enforceable via tests**:

```go
// pkg/trust/locality.go (to be created)

// INVARIANT 1: Verifiers MUST be able to validate any CapiscIO trust artifact
// using only locally cached cryptographic material and a local revocation cache.

// INVARIANT 2: Implementations MUST NOT embed synchronous registry calls
// in the verification critical path.

// INVARIANT 3: SDK and library implementations MUST provide a verification API
// that operates without network access when initialized with issuer key material.

// INVARIANT 4: Revocation data MUST be distributable as a cacheable artifact.
// Verifiers synchronize revocation state asynchronously, not per-verification.
```

---

## Next Steps

### Immediate (Phase 0.1 completion)

- [x] Audit all trust evaluation paths — **COMPLETE**
- [ ] Create `pkg/trust/locality.go` with invariant documentation
- [ ] Add locality invariant test infrastructure

### Phase 0.2 (Trust Material Lifecycle)

- [ ] Implement `TrustMaterial` struct
- [ ] Implement `JWKSCache` with soft/hard TTL
- [ ] Implement `RevocationCache` with delta sync
- [ ] Implement `Bootstrap()` function

### Phase 0.3 (Issuer/Verifier Separation)

- [ ] Add `NewVerifierWithTrustMaterial()` constructor
- [ ] Add `VerifyWithMaterial()` method variants
- [ ] Deprecate synchronous verification paths

---

**Audit Author:** AI Assistant  
**Audit Date:** 2026-05-26  
**Status:** Phase 0.1 audit complete — 7 synchronous call sites identified

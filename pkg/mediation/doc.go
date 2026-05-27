// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

// Package mediation provides runtime trust enforcement boundaries.
//
// Mediation hooks evaluate capability requests against locally cached trust
// material, enforcing RFC-001 §2.3 verification locality. They serve as the
// canonical Policy Enforcement Points (PEPs) for agent runtime operations.
//
// # Architecture
//
// The mediation system has three layers:
//
//  1. MediationHook interface — the abstraction for trust enforcement
//  2. MediationContext — carries verified trust artifacts and cached material
//  3. Decision types — structured enforcement outcomes with audit trails
//
// # Verification Locality Invariant (RFC-001 §2.3)
//
// All mediation hooks MUST operate without synchronous network calls.
// Trust material is injected via MediationContext.TrustMaterial, which contains
// pre-cached JWKS and revocation data. This enables:
//
//   - Consistent sub-millisecond enforcement latency
//   - Operation during network partitions (degraded mode)
//   - No external dependencies in the critical path
//
// # Event Emission
//
// Mediation hooks emit RFC-011 runtime events as a side effect of enforcement
// decisions. Events are evidence of what happened — they do not drive decisions.
// Event emission is asynchronous and MUST NOT block the mediation path.
//
// # Usage
//
// Gateway middleware injects trust material during bootstrap:
//
//	manager, _ := trust.NewMaterialManager(config, logger)
//	manager.Bootstrap(ctx)
//
//	hook := mediation.NewToolHook(mediation.ToolHookConfig{
//	    Logger: logger,
//	})
//
//	// During request handling:
//	mctx := &mediation.Context{
//	    TrustMaterial: manager,
//	    Badge:         verifiedBadge,
//	    Envelope:      verifiedEnvelope,
//	}
//	result, err := hook.Mediate(ctx, mctx, toolRequest)
//
// # Hook Types
//
// The package provides specialized hooks for different capability domains:
//
//   - ToolHook — tool invocation mediation (MCP tools, function calls)
//   - FilesystemHook — filesystem access mediation with path canonicalization
//   - NetworkHook — network access mediation with URL canonicalization
//   - ShellHook — shell execution mediation with command classification
package mediation

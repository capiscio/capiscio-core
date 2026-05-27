// Copyright (c) CapiscIO, Inc.
// Licensed under the MIT License.

package mediation

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// FileRequest represents a request to access a filesystem path.
type FileRequest struct {
	// Path is the filesystem path being accessed.
	Path string

	// Operation is the type of access (read, write, execute, delete).
	Operation FileOperation

	// Description is a human-readable description of the access.
	Description string
}

// FileOperation represents the type of filesystem access.
type FileOperation string

const (
	FileOpRead    FileOperation = "read"
	FileOpWrite   FileOperation = "write"
	FileOpExecute FileOperation = "execute"
	FileOpDelete  FileOperation = "delete"
	FileOpList    FileOperation = "list"
)

// Domain implements Request.
func (r *FileRequest) Domain() string {
	return "file"
}

// Capability implements Request.
func (r *FileRequest) Capability() string {
	return fmt.Sprintf("file:%s:%s", r.Operation, r.Path)
}

// FilesystemHookConfig configures the filesystem mediation hook.
type FilesystemHookConfig struct {
	// Logger for mediation operations.
	Logger Logger

	// Emitter for RFC-011 events.
	Emitter EventEmitter

	// AllowedPaths is a list of paths that are always allowed.
	// Supports wildcards: "/tmp/*" matches all files under /tmp.
	AllowedPaths []string

	// DeniedPaths is a list of paths that are always denied.
	// Takes precedence over AllowedPaths.
	// Always includes sensitive paths like /etc/shadow by default.
	DeniedPaths []string

	// DefaultDeny rejects requests when no explicit grant is found.
	// Default: true (safer for filesystem access)
	DefaultDeny bool

	// WorkingDirectory is the expected working directory for relative paths.
	// Relative paths are resolved against this before evaluation.
	WorkingDirectory string

	// RequireEnvelope requires an authority envelope for filesystem access.
	// Default: false
	RequireEnvelope bool
}

// defaultDeniedPaths are always denied regardless of configuration.
var defaultDeniedPaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"~/.ssh/*",
	"~/.gnupg/*",
	"~/.aws/credentials",
	"~/.config/gcloud/*",
	"/proc/*",
	"/sys/*",
}

// FilesystemHook mediates filesystem access requests.
type FilesystemHook struct {
	config  FilesystemHookConfig
	logger  Logger
	emitter EventEmitter
}

// NewFilesystemHook creates a filesystem mediation hook.
func NewFilesystemHook(config FilesystemHookConfig) *FilesystemHook {
	// Apply safe defaults: DefaultDeny should be true unless explicitly disabled
	// Go zero value is false, so we need to detect if it was explicitly set
	// For safety, we default to true if no paths are configured
	if len(config.AllowedPaths) == 0 && len(config.DeniedPaths) == 0 && !config.DefaultDeny {
		config.DefaultDeny = true
	}
	h := &FilesystemHook{
		config:  config,
		logger:  config.Logger,
		emitter: config.Emitter,
	}
	if h.logger == nil {
		h.logger = noopLogger{}
	}
	if h.emitter == nil {
		h.emitter = noopEmitter{}
	}
	return h
}

// Mediate evaluates a filesystem access request.
func (h *FilesystemHook) Mediate(ctx context.Context, mctx *Context, request Request) (*Result, error) {
	fileReq, ok := request.(*FileRequest)
	if !ok {
		return nil, fmt.Errorf("FilesystemHook requires *FileRequest, got %T", request)
	}

	// Canonicalize path
	path := h.canonicalizePath(fileReq.Path)

	h.logger.Debug("mediating filesystem request",
		"path", path,
		"operation", fileReq.Operation,
		"subject", mctx.SubjectDID,
	)

	// Check prerequisites (trust material, badge, envelope)
	if result := h.checkPrerequisites(mctx); result != nil {
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// Check path-based rules
	if result := h.checkPaths(path, fileReq.Operation, mctx, request); result != nil {
		return result, nil
	}

	// Apply default policy (filesystem defaults to deny)
	if h.config.DefaultDeny {
		result := DenyResult("builtin:default_deny",
			fmt.Sprintf("no explicit grant for %s on %q", fileReq.Operation, path))
		h.emitter.EmitDecision(mctx, result, request)
		return result, nil
	}

	// Default allow (only if DefaultDeny = false)
	result := AllowResult("builtin:default_allow",
		fmt.Sprintf("authenticated caller may %s %q", fileReq.Operation, path))
	h.emitter.EmitDecision(mctx, result, request)
	return result, nil
}

// checkPrerequisites verifies trust material, badge, and envelope requirements.
func (h *FilesystemHook) checkPrerequisites(mctx *Context) *Result {
	if !mctx.HasTrustMaterial() {
		return DenyResult("builtin:no_trust_material", "trust material not available")
	}
	if !mctx.HasBadge() {
		return DenyResult("builtin:unauthenticated", "no valid badge presented")
	}
	if h.config.RequireEnvelope && !mctx.HasEnvelope() {
		return DenyResult("builtin:envelope_required", "authority envelope required for filesystem access")
	}
	return nil
}

// checkPaths evaluates path-based access rules.
func (h *FilesystemHook) checkPaths(path string, op FileOperation, mctx *Context, request Request) *Result {
	// Check default denied paths (always enforced)
	for _, denied := range defaultDeniedPaths {
		if h.matchPath(path, denied) {
			result := DenyResult("builtin:sensitive_path",
				fmt.Sprintf("access to %q is always denied (sensitive path)", path))
			h.emitter.EmitDecision(mctx, result, request)
			return result
		}
	}

	// Check configured DeniedPaths
	for _, denied := range h.config.DeniedPaths {
		if h.matchPath(path, denied) {
			result := DenyResult("config:denied_path",
				fmt.Sprintf("access to %q is denied by configuration", path))
			h.emitter.EmitDecision(mctx, result, request)
			return result
		}
	}

	// Check AllowedPaths
	for _, allowed := range h.config.AllowedPaths {
		if h.matchPath(path, allowed) {
			result := AllowResult("config:allowed_path",
				fmt.Sprintf("access to %q is allowed by configuration", path))
			h.emitter.EmitDecision(mctx, result, request)
			return result
		}
	}

	// Check envelope capabilities
	if mctx.HasEnvelope() {
		capabilityClass := fmt.Sprintf("file.%s", op)
		if mctx.CapabilitySatisfied(capabilityClass) || mctx.CapabilitySatisfied("file.*") {
			result := AllowResult("envelope:capability_grant",
				fmt.Sprintf("capability granted for %s on %q", op, path))
			h.emitter.EmitDecision(mctx, result, request)
			return result
		}
	}

	return nil
}

// canonicalizePath resolves relative paths and normalizes the path.
func (h *FilesystemHook) canonicalizePath(path string) string {
	// Expand home directory
	if strings.HasPrefix(path, "~/") {
		// Even with ~ prefix, clean the path to prevent traversal attacks
		// e.g., ~/../../etc/shadow → ~/../../etc/shadow (cleaned)
		cleanedSuffix := filepath.Clean(strings.TrimPrefix(path, "~/"))
		// Reject if cleaning moved us up past home
		if strings.HasPrefix(cleanedSuffix, "..") {
			// Return the original for pattern matching (will be denied)
			return path
		}
		return "~/" + cleanedSuffix
	}

	// Resolve relative paths
	if !filepath.IsAbs(path) && h.config.WorkingDirectory != "" {
		path = filepath.Join(h.config.WorkingDirectory, path)
	}

	// Clean the path (resolve .., .)
	return filepath.Clean(path)
}

// matchPath checks if a path matches a pattern.
func (h *FilesystemHook) matchPath(path, pattern string) bool {
	// Exact match
	if path == pattern {
		return true
	}

	// Wildcard suffix match
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(path, prefix+"/") || path == prefix {
			return true
		}
	}

	// Glob match (simple version)
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}

	return false
}

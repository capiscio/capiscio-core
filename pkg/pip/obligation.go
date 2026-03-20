package pip

import (
	"context"
	"fmt"
	"log/slog"
)

// ObligationHandler processes a specific type of obligation returned by the PDP.
type ObligationHandler interface {
	// Handle attempts to enforce an obligation.
	// Returns nil if successful, error if enforcement failed.
	Handle(ctx context.Context, obligation Obligation) error

	// Supports returns true if this handler recognizes the obligation type.
	Supports(obligationType string) bool
}

// ObligationResult summarizes obligation enforcement for a request.
type ObligationResult struct {
	// Proceed is true if the request should continue after obligation processing.
	Proceed bool

	// Errors contains any obligation enforcement errors (for logging).
	Errors []ObligationError
}

// ObligationError captures a single obligation enforcement failure.
type ObligationError struct {
	Type    string
	Known   bool
	Message string
}

// ObligationRegistry maps obligation types to handlers and enforces
// the RFC-005 §7.2 enforcement mode matrix.
type ObligationRegistry struct {
	handlers []ObligationHandler
	logger   *slog.Logger
}

// NewObligationRegistry creates a new obligation registry.
func NewObligationRegistry(logger *slog.Logger) *ObligationRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &ObligationRegistry{
		logger: logger,
	}
}

// Register adds an obligation handler to the registry.
func (r *ObligationRegistry) Register(handler ObligationHandler) {
	r.handlers = append(r.handlers, handler)
}

// findHandler returns the handler for an obligation type, or nil if unknown.
func (r *ObligationRegistry) findHandler(obligationType string) ObligationHandler {
	for _, h := range r.handlers {
		if h.Supports(obligationType) {
			return h
		}
	}
	return nil
}

// Enforce processes obligations according to the enforcement mode matrix.
//
// RFC-005 §7.2 matrix:
//
//	| Mode        | Known Obligation          | Unknown Obligation     |
//	|-------------|---------------------------|------------------------|
//	| EM-OBSERVE  | Log, do not enforce       | Log, skip              |
//	| EM-GUARD    | Log, best-effort, no block| Log, skip              |
//	| EM-DELEGATE | MUST attempt, log failure | Log warning, proceed   |
//	| EM-STRICT   | MUST enforce, block fail  | MUST DENY              |
func (r *ObligationRegistry) Enforce(ctx context.Context, mode EnforcementMode, obligations []Obligation) ObligationResult {
	result := ObligationResult{Proceed: true}

	for _, ob := range obligations {
		handler := r.findHandler(ob.Type)
		known := handler != nil

		switch mode {
		case EMObserve:
			// Log only, never enforce, never block
			r.logger.InfoContext(ctx, "obligation observed (EM-OBSERVE, not enforced)",
				slog.String("obligation_type", ob.Type),
				slog.Bool("known", known),
			)

		case EMGuard:
			if known {
				// Best-effort: attempt but don't block on failure
				if err := handler.Handle(ctx, ob); err != nil {
					r.logger.WarnContext(ctx, "obligation enforcement failed (EM-GUARD, non-blocking)",
						slog.String("obligation_type", ob.Type),
						slog.String("error", err.Error()),
					)
					result.Errors = append(result.Errors, ObligationError{
						Type: ob.Type, Known: true, Message: err.Error(),
					})
				}
			} else {
				r.logger.InfoContext(ctx, "unknown obligation skipped (EM-GUARD)",
					slog.String("obligation_type", ob.Type),
				)
			}

		case EMDelegate:
			if known {
				// MUST attempt, log failure, don't block
				if err := handler.Handle(ctx, ob); err != nil {
					r.logger.WarnContext(ctx, "obligation enforcement failed (EM-DELEGATE, non-blocking)",
						slog.String("obligation_type", ob.Type),
						slog.String("error", err.Error()),
					)
					result.Errors = append(result.Errors, ObligationError{
						Type: ob.Type, Known: true, Message: err.Error(),
					})
				}
			} else {
				r.logger.WarnContext(ctx, "unknown obligation encountered (EM-DELEGATE, proceeding)",
					slog.String("obligation_type", ob.Type),
				)
				result.Errors = append(result.Errors, ObligationError{
					Type: ob.Type, Known: false, Message: "unknown obligation type",
				})
			}

		case EMStrict:
			if known {
				// MUST enforce, block on failure
				if err := handler.Handle(ctx, ob); err != nil {
					r.logger.ErrorContext(ctx, "obligation enforcement failed (EM-STRICT, BLOCKING)",
						slog.String("obligation_type", ob.Type),
						slog.String("error", err.Error()),
					)
					result.Proceed = false
					result.Errors = append(result.Errors, ObligationError{
						Type: ob.Type, Known: true, Message: err.Error(),
					})
					return result
				}
			} else {
				// Unknown obligation in EM-STRICT → MUST DENY (§7.3)
				r.logger.ErrorContext(ctx, "unknown obligation in EM-STRICT — DENY",
					slog.String("obligation_type", ob.Type),
				)
				result.Proceed = false
				result.Errors = append(result.Errors, ObligationError{
					Type:    ob.Type,
					Known:   false,
					Message: fmt.Sprintf("unknown obligation type %q in EM-STRICT — must deny", ob.Type),
				})
				return result
			}
		}
	}

	return result
}

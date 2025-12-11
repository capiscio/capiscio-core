package simpleguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type contextKey string

const (
	ContextKeySubject contextKey = "capiscio-subject"
	ContextKeyClaims  contextKey = "capiscio-claims"
)

// Middleware creates a net/http middleware for SimpleGuard.
func Middleware(guard *SimpleGuard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// 1. Extract Token (RFC-002 §9.1)
			token := r.Header.Get("X-Capiscio-Badge")
			if token == "" {
				http.Error(w, "Missing X-Capiscio-Badge header", http.StatusUnauthorized)
				return
			}

			// 2. Read Body with size limit to prevent memory exhaustion
			var bodyBytes []byte
			if r.Body != nil {
				maxSize := guard.config.MaxBodySize
				lr := &io.LimitedReader{R: r.Body, N: maxSize + 1}
				var err error
				bodyBytes, err = io.ReadAll(lr)
				if err != nil {
					http.Error(w, "Failed to read request body", http.StatusInternalServerError)
					return
				}
				if int64(len(bodyBytes)) > maxSize {
					http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				// Restore body for downstream handlers
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// 3. Verify
			claims, err := guard.VerifyInbound(token, bodyBytes)
			if err != nil {
				// Log detailed error internally for debugging
				log.Printf("SimpleGuard: verification failed: %v", err)
				// Return generic error to client to avoid leaking implementation details
				http.Error(w, "Authentication Failed", http.StatusForbidden)
				return
			}

			// 4. Add Telemetry (measures verification time only)
			duration := time.Since(start)
			w.Header().Set("Server-Timing", fmt.Sprintf("capiscio-auth;dur=%.3f", float64(duration.Microseconds())/1000.0))

			// 5. Inject Context (preferred way to access claims)
			ctx := context.WithValue(r.Context(), ContextKeySubject, claims.Subject)
			ctx = context.WithValue(ctx, ContextKeyClaims, claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SubjectFromContext retrieves the verified subject from the request context.
// Returns empty string if not found.
func SubjectFromContext(ctx context.Context) string {
	if v := ctx.Value(ContextKeySubject); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ClaimsFromContext retrieves the verified claims from the request context.
// Returns nil if not found.
func ClaimsFromContext(ctx context.Context) *Claims {
	if v := ctx.Value(ContextKeyClaims); v != nil {
		if c, ok := v.(*Claims); ok {
			return c
		}
	}
	return nil
}

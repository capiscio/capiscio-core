package simpleguard

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

			// 1. Extract Token
			token := r.Header.Get("X-Capiscio-JWS")
			if token == "" {
				http.Error(w, "Missing X-Capiscio-JWS header", http.StatusUnauthorized)
				return
			}

			// 2. Read Body
			var bodyBytes []byte
			if r.Body != nil {
				var err error
				bodyBytes, err = io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "Failed to read request body", http.StatusInternalServerError)
					return
				}
				// Restore body for downstream handlers
				r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// 3. Verify
			claims, err := guard.VerifyInbound(token, bodyBytes)
			if err != nil {
				http.Error(w, fmt.Sprintf("Security Verification Failed: %v", err), http.StatusForbidden)
				return
			}

			// 4. Add Telemetry
			duration := time.Since(start)
			w.Header().Set("Server-Timing", fmt.Sprintf("capiscio-auth;dur=%.3f", float64(duration.Microseconds())/1000.0))

			// 5. Inject Context
			ctx := context.WithValue(r.Context(), ContextKeySubject, claims.Subject)
			ctx = context.WithValue(ctx, ContextKeyClaims, claims)
			
			// 6. Set Headers for convenience
			r.Header.Set("X-Capiscio-Subject", claims.Subject)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

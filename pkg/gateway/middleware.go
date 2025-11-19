package gateway

import (
	"log"
	"net/http"
	"strings"

	"github.com/capiscio/capiscio-core/pkg/badge"
)

// NewAuthMiddleware creates a middleware that enforces Badge validity.
func NewAuthMiddleware(verifier *badge.Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Badge
		token := ExtractBadge(r)
		if token == "" {
			http.Error(w, "Missing Trust Badge", http.StatusUnauthorized)
			return
		}

		// Verify
		claims, err := verifier.Verify(r.Context(), token)
		if err != nil {
			log.Printf("Verification failed: %v", err)
			http.Error(w, "Invalid Trust Badge", http.StatusUnauthorized)
			return
		}

		// Forward verified identity to upstream
		r.Header.Set("X-Capiscio-Subject", claims.Subject)
		r.Header.Set("X-Capiscio-Issuer", claims.Issuer)

		next.ServeHTTP(w, r)
	})
}

// ExtractBadge retrieves the badge from headers.
func ExtractBadge(r *http.Request) string {
	// 1. X-Capiscio-Badge
	if token := r.Header.Get("X-Capiscio-Badge"); token != "" {
		return token
	}

	// 2. Authorization: Bearer
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/capiscio/capiscio-core/pkg/simpleguard"
)

func main() {
	// 1. Initialize SimpleGuard in DevMode
	// This will auto-generate ephemeral keys for the server
	// In a real scenario, you would load keys from disk/env
	cfg := simpleguard.Config{
		AgentID: "server-agent",
		DevMode: true,
	}

	guard, err := simpleguard.New(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize SimpleGuard: %v", err)
	}

	// 2. Create a handler
	pingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The middleware has already verified the request
		// We can access the subject from the context or header
		subject := r.Header.Get("X-Capiscio-Subject")

		// Read the body (it was restored by middleware)
		body, _ := io.ReadAll(r.Body)

		log.Printf("✅ Received verified request from: %s", subject)
		log.Printf("   Body: %s", string(body))

		response := map[string]string{
			"message": "pong",
			"reply_to": subject,
			"verified": "true",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// 3. Wrap handler with Middleware
	// We only protect /ping
	mux := http.NewServeMux()
	mux.Handle("/ping", simpleguard.Middleware(guard)(pingHandler))

	log.Println("🛡️  Secure Ping Pong Server running on :8080")
	log.Println("   Waiting for signed requests...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

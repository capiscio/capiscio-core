package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/capiscio/capiscio-core/v2/pkg/simpleguard"
)

func main() {
	// 1. Initialize SimpleGuard with shared demo keys
	// In a real scenario, you would load keys from disk/env/KMS
	seedBytes, err := hex.DecodeString("44b86d311e52d166fa2a17fcf4cde823785bd07f0ccaa9528e4202d090d92c2a")
	if err != nil {
		log.Fatalf("Failed to decode seed: %v", err)
	}
	pubBytes, err := hex.DecodeString("04a566503aea697e71e76616992815aa09daa5b850255b5dbfd3379172bf3480")
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	// Go's ed25519.PrivateKey is 64 bytes (seed + pub), so we generate it from the 32-byte seed
	privKey := ed25519.NewKeyFromSeed(seedBytes)

	cfg := simpleguard.Config{
		AgentID:    "demo-agent",
		PrivateKey: privKey,
		PublicKey:  ed25519.PublicKey(pubBytes),
		KeyID:      "demo-key-1",
	}

	guard, err := simpleguard.New(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize SimpleGuard: %v", err)
	}

	// 2. Create a handler
	pingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The middleware has already verified the request
		// Get the subject from context (preferred way)
		subject := simpleguard.SubjectFromContext(r.Context())

		// Read the body (it was restored by middleware)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
			return
		}

		log.Printf("✅ Received verified request from: %s", subject)
		log.Printf("   Body: %s", string(body))

		response := map[string]string{
			"message":  "pong",
			"reply_to": subject,
			"verified": "true",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Failed to encode response: %v", err)
		}
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

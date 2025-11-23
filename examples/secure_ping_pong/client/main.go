package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/capiscio/capiscio-core/pkg/simpleguard"
	"github.com/go-jose/go-jose/v4"
)

func main() {
	// 1. Initialize SimpleGuard with shared demo keys
	seedBytes, _ := hex.DecodeString("44b86d311e52d166fa2a17fcf4cde823785bd07f0ccaa9528e4202d090d92c2a")
	pubBytes, _ := hex.DecodeString("04a566503aea697e71e76616992815aa09daa5b850255b5dbfd3379172bf3480")

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

	client := &http.Client{Timeout: 5 * time.Second}
	url := "http://localhost:8080/ping"

	// Scenario 1: Valid Request
	fmt.Println("\n--- Scenario 1: Valid Request ---")
	sendPing(client, guard, url, "Hello Server!", false)

	// Scenario 2: Tampered Body (Simulated)
	fmt.Println("\n--- Scenario 2: Tampered Body ---")
	simulateTampering(client, guard, url)

	// Scenario 3: Replay Attack (Expired Token)
	fmt.Println("\n--- Scenario 3: Replay Attack (Expired Token) ---")
	simulateReplayAttack(client, privKey, url)
}

func sendPing(client *http.Client, guard *simpleguard.SimpleGuard, url string, message string, expectError bool) {
	// Prepare Payload
	payload := map[string]string{"msg": message}
	bodyBytes, _ := json.Marshal(payload)

	// Sign
	claims := simpleguard.Claims{
		Subject: "client-agent",
	}
	token, err := guard.SignOutbound(claims, bodyBytes)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}

	// Send
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Capiscio-JWS", token)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 200 {
		fmt.Printf("✅ Success (%d) in %v\n", resp.StatusCode, duration)
		fmt.Printf("   Response: %s\n", string(respBody))
		fmt.Printf("   Server-Timing: %s\n", resp.Header.Get("Server-Timing"))
	} else {
		fmt.Printf("❌ Failed (%d): %s\n", resp.StatusCode, string(respBody))
	}
}

func simulateTampering(client *http.Client, guard *simpleguard.SimpleGuard, url string) {
	// 1. Sign original body
	originalBody := []byte(`{"msg": "original"}`)
	claims := simpleguard.Claims{Subject: "bad-actor"}
	token, _ := guard.SignOutbound(claims, originalBody)

	// 2. Send different body
	tamperedBody := []byte(`{"msg": "tampered"}`)
	
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(tamperedBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Capiscio-JWS", token)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 403 {
		fmt.Println("✅ SUCCESS: Tampered request was blocked (403 Forbidden)")
	} else {
		fmt.Printf("❌ FAILURE: Tampered request was accepted (%d)\n", resp.StatusCode)
	}
}

func simulateReplayAttack(client *http.Client, privKey ed25519.PrivateKey, url string) {
	// Manually create an expired token
	// We can't use guard.SignOutbound because it enforces current time
	
	opts := &jose.SignerOptions{}
	opts.WithType("JWT")
	opts.WithHeader("kid", "demo-key-1")

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privKey}, opts)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	now := time.Now().Unix()
	claims := simpleguard.Claims{
		Subject:  "demo-agent",
		Issuer:   "demo-agent",
		IssuedAt: now - 120, // Issued 2 mins ago
		Expiry:   now - 60,  // Expired 1 min ago
	}

	payloadBytes, _ := json.Marshal(claims)
	jwsObj, err := signer.Sign(payloadBytes)
	if err != nil {
		log.Fatalf("Failed to sign: %v", err)
	}
	
	token, _ := jwsObj.CompactSerialize()

	// Send request
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Capiscio-JWS", token)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		fmt.Println("✅ SUCCESS: Replay/Expired token was blocked (403 Forbidden)")
	} else {
		fmt.Printf("❌ FAILURE: Expired token was accepted (%d)\n", resp.StatusCode)
	}
}

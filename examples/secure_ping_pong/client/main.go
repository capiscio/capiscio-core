package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/capiscio/capiscio-core/pkg/simpleguard"
)

func main() {
	// 1. Initialize SimpleGuard in DevMode
	// This gives us keys to sign our requests
	cfg := simpleguard.Config{
		AgentID: "client-agent",
		DevMode: true,
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
	// We can't easily simulate tampering with the high-level SignOutbound helper
	// because it calculates the hash for us. 
	// To demonstrate failure, we'd need to sign one body and send another.
	fmt.Println("\n--- Scenario 2: Tampered Body ---")
	simulateTampering(client, guard, url)
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

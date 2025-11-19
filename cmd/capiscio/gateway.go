package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/capiscio/capiscio-core/pkg/badge"
	"github.com/capiscio/capiscio-core/pkg/registry"
	"github.com/spf13/cobra"
)

var (
	gatewayPort        int
	gatewayTarget      string
	gatewayLocalKey    string
	gatewayRegistryURL string
)

var gatewayCmd = &cobra.Command{
	Use:   "gateway",
	Short: "Start the CapiscIO Gateway",
}

var gatewayStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the gateway server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Setup Registry
		var reg registry.Registry
		if gatewayLocalKey != "" {
			reg = registry.NewLocalRegistry(gatewayLocalKey)
			log.Printf("Starting Gateway in LOCAL MODE (Key: %s)", gatewayLocalKey)
		} else if gatewayRegistryURL != "" {
			reg = registry.NewCloudRegistry(gatewayRegistryURL)
			log.Printf("Starting Gateway in CLOUD MODE (Registry: %s)", gatewayRegistryURL)
		} else {
			return fmt.Errorf("must provide either --local-key or --registry-url")
		}

		// 2. Setup Verifier
		verifier := badge.NewVerifier(reg)

		// 3. Setup Proxy
		targetURL, err := url.Parse(gatewayTarget)
		if err != nil {
			return fmt.Errorf("invalid target URL: %w", err)
		}
		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		// 4. Middleware
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Badge
			token := extractBadge(r)
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
			
			proxy.ServeHTTP(w, r)
		})

		// 5. Start Server
		addr := fmt.Sprintf(":%d", gatewayPort)
		log.Printf("Gateway listening on %s -> %s", addr, gatewayTarget)
		return http.ListenAndServe(addr, handler)
	},
}

func extractBadge(r *http.Request) string {
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

func init() {
	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.AddCommand(gatewayStartCmd)

	gatewayStartCmd.Flags().IntVar(&gatewayPort, "port", 8080, "Port to listen on")
	gatewayStartCmd.Flags().StringVar(&gatewayTarget, "target", "http://localhost:3000", "Upstream target URL")
	gatewayStartCmd.Flags().StringVar(&gatewayLocalKey, "local-key", "", "Path to local public key file (JWK)")
	gatewayStartCmd.Flags().StringVar(&gatewayRegistryURL, "registry-url", "", "URL of the CapiscIO Registry")
}

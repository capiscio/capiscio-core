package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/capiscio/capiscio-core/v2/pkg/badge"
	"github.com/capiscio/capiscio-core/v2/pkg/gateway"
	"github.com/capiscio/capiscio-core/v2/pkg/registry"
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
	RunE: func(_ *cobra.Command, _ []string) error {
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
		handler := gateway.NewAuthMiddleware(verifier, proxy)

		// 5. Start Server
		addr := fmt.Sprintf(":%d", gatewayPort)
		log.Printf("Gateway listening on %s -> %s", addr, gatewayTarget)
		return http.ListenAndServe(addr, handler)
	},
}

func init() {
	rootCmd.AddCommand(gatewayCmd)
	gatewayCmd.AddCommand(gatewayStartCmd)

	gatewayStartCmd.Flags().IntVar(&gatewayPort, "port", 8080, "Port to listen on")
	gatewayStartCmd.Flags().StringVar(&gatewayTarget, "target", "http://localhost:3000", "Upstream target URL")
	gatewayStartCmd.Flags().StringVar(&gatewayLocalKey, "local-key", "", "Path to local public key file (JWK)")
	gatewayStartCmd.Flags().StringVar(&gatewayRegistryURL, "registry-url", "", "URL of the CapiscIO Registry")
}

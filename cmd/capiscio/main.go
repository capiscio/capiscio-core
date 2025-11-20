// Package main is the entry point for the CapiscIO CLI.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "1.0.2"

var rootCmd = &cobra.Command{
	Use:   "capiscio",
	Short: "CapiscIO Core Engine CLI",
	Long: `The core engine for the CapiscIO ecosystem.
Validates Agent Cards, verifies signatures, and scores agent trust and availability.`,
	Version: version,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

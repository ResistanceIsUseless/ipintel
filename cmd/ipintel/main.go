package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mgriffiths/ipintel/internal/config"
	"github.com/mgriffiths/ipintel/internal/lookup"
	"github.com/mgriffiths/ipintel/internal/output"
)

var (
	version = "dev"
)

func main() {
	var (
		jsonOutput  bool
		noSpinner   bool
		showVersion bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	flag.BoolVar(&noSpinner, "no-spinner", false, "Disable animated spinner (for piping)")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.Usage = func() {
		title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7C3AED")).Render("ipintel")
		fmt.Fprintf(os.Stderr, "%s - IP Intelligence Lookup\n\n", title)
		fmt.Fprintf(os.Stderr, "Usage: ipintel [flags] <ip-address>\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAPI Keys (via .env or environment):\n")
		fmt.Fprintf(os.Stderr, "  GREYNOISE_API_KEY    GreyNoise Community/Enterprise API key\n")
		fmt.Fprintf(os.Stderr, "  ABUSEIPDB_API_KEY    AbuseIPDB API key\n")
		fmt.Fprintf(os.Stderr, "  SHODAN_API_KEY       Shodan API key\n")
	}
	flag.Parse()

	if showVersion {
		fmt.Printf("ipintel %s\n", version)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	ipArg := flag.Arg(0)

	if ip := net.ParseIP(ipArg); ip == nil {
		fmt.Fprintf(os.Stderr, "Error: invalid IP address: %s\n", ipArg)
		os.Exit(1)
	}

	// Load .env as fallback (direnv preferred)
	config.LoadDotEnv()
	cfg := config.Load()

	ctx := context.Background()

	format := output.FormatTable
	if jsonOutput {
		format = output.FormatJSON
		noSpinner = true
	}

	var result *lookup.Result
	var err error

	if noSpinner {
		engine := lookup.NewEngine(cfg)
		result, err = engine.Run(ctx, ipArg)
	} else {
		result, err = output.RunWithSpinner(ctx, cfg, ipArg)
	}

	if err != nil {
		errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Bold(true)
		fmt.Fprintf(os.Stderr, "%s %v\n", errStyle.Render("Error:"), err)
		os.Exit(1)
	}

	if err := output.Render(os.Stdout, result, format); err != nil {
		fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
		os.Exit(1)
	}
}

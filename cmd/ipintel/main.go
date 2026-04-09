package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

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
		noAWS       bool
		noAzure     bool
		noGCP       bool
		inputFile   string
		outputMD    string
		outputCSV   string
		quiet       bool
		noCache     bool
	)

	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	flag.BoolVar(&noSpinner, "no-spinner", false, "Disable animated spinner (for piping)")
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&noAWS, "no-aws", false, "Skip AWS tenant lookup")
	flag.BoolVar(&noAzure, "no-azure", false, "Skip Azure tenant lookup")
	flag.BoolVar(&noGCP, "no-gcp", false, "Skip GCP tenant lookup")
	flag.BoolVar(&noCache, "no-cache", false, "Disable result caching")
	flag.StringVar(&inputFile, "file", "", "Read IPs/domains from file (one per line, - for stdin)")
	flag.StringVar(&outputMD, "output-md", "", "Write Markdown report to file")
	flag.StringVar(&outputCSV, "output-csv", "", "Write CSV report to file")
	flag.BoolVar(&quiet, "quiet", false, "Single-line grepable output (critical flags only)")
	flag.Usage = func() {
		title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7C3AED")).Render("ipintel")
		fmt.Fprintf(os.Stderr, "%s - IP Intelligence Lookup\n\n", title)
		fmt.Fprintf(os.Stderr, "Usage: ipintel [flags] <ip-address|domain>\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAPI Keys (via .env or environment):\n")
		fmt.Fprintf(os.Stderr, "  GREYNOISE_API_KEY     GreyNoise Community/Enterprise API key\n")
		fmt.Fprintf(os.Stderr, "  ABUSEIPDB_API_KEY     AbuseIPDB API key\n")
		fmt.Fprintf(os.Stderr, "  SHODAN_API_KEY        Shodan API key\n")
		fmt.Fprintf(os.Stderr, "  VIRUSTOTAL_API_KEY    VirusTotal API key\n")
		fmt.Fprintf(os.Stderr, "  ALIENVAULT_API_KEY    AlienVault OTX API key\n")
		fmt.Fprintf(os.Stderr, "  CENSYS_API_ID         Censys API ID\n")
		fmt.Fprintf(os.Stderr, "  CENSYS_API_SECRET     Censys API Secret\n")
		fmt.Fprintf(os.Stderr, "  IPINFO_API_KEY        IPinfo.io API key\n")
	}
	flag.Parse()

	if showVersion {
		fmt.Printf("ipintel %s\n", version)
		os.Exit(0)
	}

	// Load .env as fallback (direnv preferred)
	config.LoadDotEnv()
	cfg := config.Load()
	cfg.SkipAWS = noAWS
	cfg.SkipAzure = noAzure
	cfg.SkipGCP = noGCP
	if noCache {
		cfg.CacheEnabled = false
	}

	ctx := context.Background()

	// Determine output format
	format := output.FormatTable
	if jsonOutput {
		format = output.FormatJSON
		noSpinner = true
	}
	if quiet {
		format = output.FormatQuiet
		noSpinner = true
	}

	// Collect targets: from --file, stdin pipe, or CLI args
	var targets []string

	if inputFile != "" {
		var scanner *bufio.Scanner
		if inputFile == "-" {
			scanner = bufio.NewScanner(os.Stdin)
		} else {
			f, err := os.Open(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot open file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			scanner = bufio.NewScanner(f)
		}
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
	} else if flag.NArg() >= 1 {
		targets = flag.Args()
	} else {
		// Check if stdin is a pipe
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
		}
	}

	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Resolve all targets to IPs (supports domain names)
	var ips []string
	for _, target := range targets {
		resolved := resolveTarget(target)
		ips = append(ips, resolved...)
	}

	if len(ips) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no valid IP addresses to look up\n")
		os.Exit(1)
	}

	// Open output files if requested
	var mdFile, csvFile *os.File
	if outputMD != "" {
		f, err := os.Create(outputMD)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create markdown file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		mdFile = f
	}
	if outputCSV != "" {
		f, err := os.Create(outputCSV)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot create CSV file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		csvFile = f
	}

	errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Bold(true)

	if len(ips) == 1 {
		// Single IP mode
		ipArg := ips[0]
		var result *lookup.Result
		var err error

		if noSpinner {
			engine := lookup.NewEngine(cfg)
			result, err = engine.Run(ctx, ipArg)
		} else {
			result, err = output.RunWithSpinner(ctx, cfg, ipArg)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", errStyle.Render("Error:"), err)
			os.Exit(1)
		}

		if err := output.Render(os.Stdout, result, format); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}

		// Write to additional formats if requested
		if mdFile != nil {
			if err := output.Render(mdFile, result, output.FormatMarkdown); err != nil {
				fmt.Fprintf(os.Stderr, "Markdown output error: %v\n", err)
			}
		}
		if csvFile != nil {
			if err := output.Render(csvFile, result, output.FormatCSV); err != nil {
				fmt.Fprintf(os.Stderr, "CSV output error: %v\n", err)
			}
		}
	} else {
		// Bulk mode: process concurrently with worker pool
		const maxWorkers = 5
		sem := make(chan struct{}, maxWorkers)
		var mu sync.Mutex
		var results []*lookup.Result

		for _, ipArg := range ips {
			sem <- struct{}{}
			go func(ip string) {
				defer func() { <-sem }()
				engine := lookup.NewEngine(cfg)
				result, err := engine.Run(ctx, ip)
				if err != nil {
					mu.Lock()
					fmt.Fprintf(os.Stderr, "%s %s: %v\n", errStyle.Render("Error:"), ip, err)
					mu.Unlock()
					return
				}
				mu.Lock()
				results = append(results, result)
				// Print each result as it completes
				if err := output.Render(os.Stdout, result, format); err != nil {
					fmt.Fprintf(os.Stderr, "Output error for %s: %v\n", ip, err)
				}
				mu.Unlock()
			}(ipArg)
		}
		// Wait for all workers
		for i := 0; i < maxWorkers; i++ {
			sem <- struct{}{}
		}

		// Write bulk results to files if requested
		if mdFile != nil {
			for _, r := range results {
				if err := output.Render(mdFile, r, output.FormatMarkdown); err != nil {
					fmt.Fprintf(os.Stderr, "Markdown output error: %v\n", err)
				}
			}
		}
		if csvFile != nil {
			for i, r := range results {
				f := output.FormatCSV
				if i == 0 {
					f = output.FormatCSVHeader // include header row for first entry
				}
				if err := output.Render(csvFile, r, f); err != nil {
					fmt.Fprintf(os.Stderr, "CSV output error: %v\n", err)
				}
			}
		}
	}
}

// resolveTarget converts an IP or domain to a list of IPs.
func resolveTarget(target string) []string {
	// If it's already an IP, use it directly
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}
	}

	// Treat as domain name — resolve A and AAAA records
	ips, err := net.LookupHost(target)
	if err != nil {
		errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B"))
		fmt.Fprintf(os.Stderr, "%s Could not resolve %s: %v\n", errStyle.Render("Warning:"), target, err)
		return nil
	}

	if len(ips) > 0 {
		infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#06B6D4"))
		fmt.Fprintf(os.Stderr, "%s %s -> %s\n", infoStyle.Render("Resolved:"), target, strings.Join(ips, ", "))
	}

	return ips
}

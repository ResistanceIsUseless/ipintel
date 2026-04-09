package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ResistanceIsUseless/ipintel/internal/cache"
	"github.com/ResistanceIsUseless/ipintel/internal/config"
)

// Engine orchestrates all providers and runs lookups.
type Engine struct {
	cfg       *config.Config
	providers []Provider
	timeout   time.Duration
	cache     *cache.Cache
}

// NewEngine creates a lookup engine with all configured providers.
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		cfg:     cfg,
		timeout: 45 * time.Second,
	}

	// Initialize cache (best-effort; failure is non-fatal)
	if cfg.CacheEnabled {
		if c, err := cache.New(cfg.CacheDir, cfg.CacheTTL); err == nil {
			e.cache = c
		}
	}

	// Always-on (free) providers
	e.providers = append(e.providers, NewReverseDNS())
	e.providers = append(e.providers, NewDNSIntel())
	e.providers = append(e.providers, NewForwardDNSRecon())
	e.providers = append(e.providers, NewRDAP())
	e.providers = append(e.providers, NewASNLookup())
	e.providers = append(e.providers, NewCloudDetector())
	e.providers = append(e.providers, NewCDNDetector())
	e.providers = append(e.providers, NewCrtSh())
	e.providers = append(e.providers, NewPortScanner())
	e.providers = append(e.providers, NewWebIntel())
	e.providers = append(e.providers, NewJARMScanner())
	e.providers = append(e.providers, NewUDPScanner())
	e.providers = append(e.providers, NewThreatFox())
	e.providers = append(e.providers, NewTechStackDetector())

	// API-key providers
	if cfg.HasGreyNoise() {
		e.providers = append(e.providers, NewGreyNoise(cfg.GreyNoiseAPIKey))
	}
	if cfg.HasAbuseIPDB() {
		e.providers = append(e.providers, NewAbuseIPDB(cfg.AbuseIPDBAPIKey))
	}
	if cfg.HasShodan() {
		e.providers = append(e.providers, NewShodan(cfg.ShodanAPIKey))
	}
	if cfg.HasVirusTotal() {
		e.providers = append(e.providers, NewVirusTotal(cfg.VirusTotalAPIKey))
	}
	if cfg.HasAlienVault() {
		e.providers = append(e.providers, NewAlienVaultOTX(cfg.AlienVaultAPIKey))
	}
	if cfg.HasCensys() {
		e.providers = append(e.providers, NewCensys(cfg.CensysAPIID, cfg.CensysAPISecret))
	}
	if cfg.HasIPInfo() {
		e.providers = append(e.providers, NewIPInfo(cfg.IPInfoAPIKey))
	}

	// Authenticated tenant lookups — broad search across all accessible resources
	if cfg.HasAzureTenant() {
		e.providers = append(e.providers, NewAzureTenant())
	}
	if cfg.HasAWSTenant() {
		e.providers = append(e.providers, NewAWSTenant(AWSTenantConfig{
			SSORoleName: cfg.AWSSSORole,
			SSORegion:   cfg.AWSSSORegion,
			Profiles:    cfg.AWSProfiles,
			Regions:     cfg.AWSRegions,
		}))
	}
	if cfg.HasGCPTenant() {
		e.providers = append(e.providers, NewGCPTenant(GCPTenantConfig{
			Projects: cfg.GCPProjects,
			Regions:  cfg.GCPRegions,
		}))
	}

	return e
}

// Run executes all providers and returns the aggregated result.
//
// Providers are executed in two phases:
//   - Phase 1: All providers that do NOT implement HostnameAwareProvider run
//     concurrently. These include DNS, RDAP, ASN, cloud, threat intel, etc.
//   - Phase 2: Providers implementing HostnameAwareProvider (WebIntel, JARM,
//     TechStack) run after phase 1 completes. They receive hostnames discovered
//     by phase-1 providers (rDNS, crt.sh, forward DNS) via SetHostnames, enabling
//     proper SNI and Host header routing for accurate service fingerprinting.
func (e *Engine) Run(ctx context.Context, ipStr string) (*Result, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Check cache first
	if e.cache != nil {
		if data, ok := e.cache.Get(ipStr); ok {
			var cached Result
			if err := json.Unmarshal(data, &cached); err == nil {
				return &cached, nil
			}
		}
	}

	isPrivate := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	result := &Result{
		IP:        ipStr,
		IsPrivate: isPrivate,
		Timestamp: time.Now().UTC(),
	}

	// Filter providers for private IPs — only run providers that explicitly support it
	providers := e.providers
	if isPrivate {
		var filtered []Provider
		for _, p := range providers {
			if pp, ok := p.(PrivateIPProvider); ok && pp.SupportsPrivateIP() {
				filtered = append(filtered, p)
			}
		}
		providers = filtered
	}

	// Split into phase-1 (standard) and phase-2 (hostname-aware) providers
	var phase1 []Provider
	var phase2 []HostnameAwareProvider
	for _, p := range providers {
		if hap, ok := p.(HostnameAwareProvider); ok {
			phase2 = append(phase2, hap)
		} else {
			phase1 = append(phase1, p)
		}
	}

	// --- Phase 1: Run standard providers concurrently ---
	runProviders(ctx, phase1, ip, result)

	// --- Collect hostnames from phase-1 results ---
	hostnames := collectHostnames(result)

	// --- Phase 2: Run hostname-aware providers concurrently ---
	if len(phase2) > 0 {
		for _, hap := range phase2 {
			hap.SetHostnames(hostnames)
		}
		// Convert back to []Provider for the runner
		p2 := make([]Provider, len(phase2))
		for i, hap := range phase2 {
			p2[i] = hap
		}
		runProviders(ctx, p2, ip, result)
	}

	// Store result in cache (best-effort)
	if e.cache != nil {
		e.cache.Put(ipStr, result)
	}

	return result, nil
}

// runProviders executes a slice of providers concurrently against the given IP,
// collecting results and errors into the shared Result.
func runProviders(ctx context.Context, providers []Provider, ip net.IP, result *Result) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range providers {
		wg.Add(1)
		go func(prov Provider) {
			defer wg.Done()
			if err := prov.Lookup(ctx, ip); err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, ProviderError{
					Provider: prov.Name(),
					Error:    err.Error(),
				})
				mu.Unlock()
				return
			}
			mu.Lock()
			prov.Apply(result)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
}

// collectHostnames extracts unique hostnames discovered by phase-1 providers.
// Sources: reverse DNS PTR records, crt.sh certificate SANs/CN, forward DNS
// hostname, and forward-confirmed rDNS entries.
func collectHostnames(result *Result) []string {
	seen := make(map[string]bool)
	var hostnames []string

	add := func(h string) {
		h = strings.TrimSuffix(strings.TrimSpace(h), ".")
		if h == "" || seen[h] {
			return
		}
		// Skip wildcard entries
		if strings.HasPrefix(h, "*.") || strings.HasPrefix(h, "*") {
			return
		}
		seen[h] = true
		hostnames = append(hostnames, h)
	}

	// Reverse DNS PTR records
	for _, ptr := range result.ReverseDNS {
		add(ptr)
	}

	// crt.sh certificates
	for _, cert := range result.Certificates {
		add(cert.CommonName)
		// SANs field is a comma-separated string
		if cert.SANs != "" {
			for _, san := range strings.Split(cert.SANs, ",") {
				add(san)
			}
		}
	}

	// Forward DNS hostname
	if result.ForwardDNS != nil && result.ForwardDNS.Hostname != "" {
		add(result.ForwardDNS.Hostname)
	}

	// Forward-Confirmed rDNS
	if result.DNSIntel != nil {
		for _, entry := range result.DNSIntel.FCrDNS {
			if entry.Confirmed {
				add(entry.PTR)
			}
		}
	}

	return hostnames
}

// ProviderNames returns a list of active provider names.
func (e *Engine) ProviderNames() []string {
	names := make([]string, len(e.providers))
	for i, p := range e.providers {
		names[i] = p.Name()
	}
	return names
}

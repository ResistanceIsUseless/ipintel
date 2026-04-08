package lookup

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mgriffiths/ipintel/internal/config"
)

// Engine orchestrates all providers and runs lookups.
type Engine struct {
	cfg       *config.Config
	providers []Provider
	timeout   time.Duration
}

// NewEngine creates a lookup engine with all configured providers.
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{
		cfg:     cfg,
		timeout: 45 * time.Second,
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

	return e
}

// Run executes all providers concurrently and returns the aggregated result.
func (e *Engine) Run(ctx context.Context, ipStr string) (*Result, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
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
	return result, nil
}

// ProviderNames returns a list of active provider names.
func (e *Engine) ProviderNames() []string {
	names := make([]string, len(e.providers))
	for i, p := range e.providers {
		names[i] = p.Name()
	}
	return names
}

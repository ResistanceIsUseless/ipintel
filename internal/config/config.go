package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config holds all API keys and settings.
type Config struct {
	GreyNoiseAPIKey  string
	AbuseIPDBAPIKey  string
	ShodanAPIKey     string
	VirusTotalAPIKey string

	// Azure: uses DefaultAzureCredential (az login, env vars, managed identity).
	// Resource Graph searches all subscriptions the credential has access to.
	AzureEnabled bool

	// AWS: uses default credential chain per profile.
	// SSO mode: discovers all org accounts and assumes a role in each.
	// Profile mode: uses explicit CLI profiles (fallback).
	AWSSSORole   string   // SSO role to assume in each account (e.g., "ReadOnlyAccess")
	AWSSSORegion string   // SSO portal region (e.g., "us-east-1")
	AWSProfiles  []string // AWS CLI profile names (fallback if SSO not configured)
	AWSRegions   []string // regions to search (empty = all major regions)
	AWSEnabled   bool

	// Runtime overrides (set via CLI flags, not env)
	SkipAWS   bool
	SkipAzure bool
}

// Load reads configuration from environment variables.
// Expects .env to be loaded via direnv or similar.
func Load() *Config {
	cfg := &Config{
		GreyNoiseAPIKey:  os.Getenv("GREYNOISE_API_KEY"),
		AbuseIPDBAPIKey:  os.Getenv("ABUSEIPDB_API_KEY"),
		ShodanAPIKey:     os.Getenv("SHODAN_API_KEY"),
		VirusTotalAPIKey: os.Getenv("VIRUSTOTAL_API_KEY"),
	}

	// Azure: enabled if AZURE_TENANT_ENABLED=true or legacy AZURE_SUBSCRIPTION_ID is set,
	// or if AZURE_TENANT_ID env var is present (service principal).
	cfg.AzureEnabled = os.Getenv("AZURE_TENANT_ENABLED") == "true" ||
		os.Getenv("AZURE_SUBSCRIPTION_ID") != "" ||
		os.Getenv("AZURE_TENANT_ID") != ""

	// AWS: enabled if any signal is present
	cfg.AWSEnabled = os.Getenv("AWS_TENANT_ENABLED") == "true" ||
		os.Getenv("AWS_ACCESS_KEY_ID") != "" ||
		os.Getenv("AWS_PROFILE") != "" ||
		os.Getenv("AWS_PROFILES") != "" ||
		os.Getenv("AWS_SSO_ROLE") != ""

	cfg.AWSSSORole = os.Getenv("AWS_SSO_ROLE")
	cfg.AWSSSORegion = os.Getenv("AWS_SSO_REGION")

	cfg.AWSProfiles = parseCSVEnv("AWS_PROFILES")
	// Also include AWS_PROFILE if set and not already in the list
	if single := os.Getenv("AWS_PROFILE"); single != "" {
		found := false
		for _, p := range cfg.AWSProfiles {
			if p == single {
				found = true
				break
			}
		}
		if !found {
			cfg.AWSProfiles = append(cfg.AWSProfiles, single)
		}
	}

	cfg.AWSRegions = parseCSVEnv("AWS_REGIONS")
	// Backward compat: if only AWS_REGION is set, use it
	if len(cfg.AWSRegions) == 0 {
		if r := os.Getenv("AWS_REGION"); r != "" {
			cfg.AWSRegions = []string{r}
		}
	}

	return cfg
}

// HasGreyNoise returns true if a GreyNoise API key is configured.
func (c *Config) HasGreyNoise() bool {
	return c.GreyNoiseAPIKey != ""
}

// HasAbuseIPDB returns true if an AbuseIPDB API key is configured.
func (c *Config) HasAbuseIPDB() bool {
	return c.AbuseIPDBAPIKey != ""
}

// HasShodan returns true if a Shodan API key is configured.
func (c *Config) HasShodan() bool {
	return c.ShodanAPIKey != ""
}

// HasVirusTotal returns true if a VirusTotal API key is configured.
func (c *Config) HasVirusTotal() bool {
	return c.VirusTotalAPIKey != ""
}

// HasAzureTenant returns true if Azure tenant lookup is enabled.
// Auth uses DefaultAzureCredential which supports az login, env vars, and managed identity.
// Resource Graph searches all subscriptions the credential can access.
func (c *Config) HasAzureTenant() bool {
	return c.AzureEnabled && !c.SkipAzure
}

// HasAWSTenant returns true if AWS tenant lookup is enabled.
// Searches across all configured profiles and regions.
func (c *Config) HasAWSTenant() bool {
	return c.AWSEnabled && !c.SkipAWS
}

// LoadDotEnv is a simple .env file loader. It reads key=value pairs
// and sets them as environment variables if not already set.
func LoadDotEnv() {
	paths := []string{".env"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".env"))
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok {
				k = strings.TrimSpace(k)
				k = strings.TrimPrefix(k, "export ")
				v = strings.TrimSpace(v)
				if os.Getenv(k) == "" {
					os.Setenv(k, v)
				}
			}
		}
	}
}

// parseCSVEnv reads a comma-separated env var into a string slice.
func parseCSVEnv(key string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

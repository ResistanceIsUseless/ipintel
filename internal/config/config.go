package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config holds all API keys and settings.
type Config struct {
	GreyNoiseAPIKey   string
	AbuseIPDBAPIKey   string
	ShodanAPIKey      string
	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string
	AWSRegion         string
}

// Load reads configuration from environment variables.
// Expects .env to be loaded via direnv or similar.
func Load() *Config {
	return &Config{
		GreyNoiseAPIKey:   os.Getenv("GREYNOISE_API_KEY"),
		AbuseIPDBAPIKey:   os.Getenv("ABUSEIPDB_API_KEY"),
		ShodanAPIKey:      os.Getenv("SHODAN_API_KEY"),
		AzureTenantID:     os.Getenv("AZURE_TENANT_ID"),
		AzureClientID:     os.Getenv("AZURE_CLIENT_ID"),
		AzureClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
		AWSRegion:         getEnvDefault("AWS_REGION", "us-east-1"),
	}
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

func getEnvDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

package config

import (
	"os"
	"path/filepath"
	"strings"
)

// Config holds all API keys and settings.
type Config struct {
	GreyNoiseAPIKey     string
	AbuseIPDBAPIKey     string
	ShodanAPIKey        string
	VirusTotalAPIKey    string
	AzureTenantID       string
	AzureClientID       string
	AzureClientSecret   string
	AzureSubscriptionID string
	AWSRegion           string
}

// Load reads configuration from environment variables.
// Expects .env to be loaded via direnv or similar.
func Load() *Config {
	return &Config{
		GreyNoiseAPIKey:     os.Getenv("GREYNOISE_API_KEY"),
		AbuseIPDBAPIKey:     os.Getenv("ABUSEIPDB_API_KEY"),
		ShodanAPIKey:        os.Getenv("SHODAN_API_KEY"),
		VirusTotalAPIKey:    os.Getenv("VIRUSTOTAL_API_KEY"),
		AzureTenantID:       os.Getenv("AZURE_TENANT_ID"),
		AzureClientID:       os.Getenv("AZURE_CLIENT_ID"),
		AzureClientSecret:   os.Getenv("AZURE_CLIENT_SECRET"),
		AzureSubscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"),
		AWSRegion:           getEnvDefault("AWS_REGION", "us-east-1"),
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

// HasVirusTotal returns true if a VirusTotal API key is configured.
func (c *Config) HasVirusTotal() bool {
	return c.VirusTotalAPIKey != ""
}

// HasAzureTenant returns true if Azure subscription ID is configured.
// Authentication uses DefaultAzureCredential (az login, env vars, managed identity).
func (c *Config) HasAzureTenant() bool {
	return c.AzureSubscriptionID != ""
}

// HasAWSTenant returns true if AWS credentials are available.
// Authentication uses the default credential chain (env, ~/.aws/credentials, instance role).
func (c *Config) HasAWSTenant() bool {
	// AWS SDK uses its own credential chain; we just need to know the user wants it.
	// We check for explicit region config or AWS env vars as a signal.
	return os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_PROFILE") != "" || os.Getenv("AWS_TENANT_ENABLED") == "true"
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

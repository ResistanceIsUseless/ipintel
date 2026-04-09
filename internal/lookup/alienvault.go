package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// AlienVaultOTX queries the AlienVault Open Threat Exchange for IP intelligence.
// Free API with optional API key for higher rate limits.
type AlienVaultOTX struct {
	apiKey string
	result *AlienVaultResult
}

func NewAlienVaultOTX(apiKey string) *AlienVaultOTX {
	return &AlienVaultOTX{apiKey: apiKey}
}

func (a *AlienVaultOTX) Name() string { return "alienvault" }

func (a *AlienVaultOTX) Lookup(ctx context.Context, ip net.IP) error {
	ipStr := ip.String()

	// Fetch general info and reputation
	generalURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ipStr)
	if ip.To4() == nil {
		generalURL = fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv6/%s/general", ipStr)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", generalURL, nil)
	if err != nil {
		return err
	}
	if a.apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", a.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("AlienVault OTX request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AlienVault OTX returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var otxResp otxGeneralResponse
	if err := json.Unmarshal(body, &otxResp); err != nil {
		return fmt.Errorf("AlienVault OTX parse error: %w", err)
	}

	a.result = &AlienVaultResult{
		PulseCount: otxResp.PulseInfo.Count,
		Reputation: otxResp.Reputation,
		Country:    otxResp.CountryCode,
		ASN:        otxResp.ASN,
		Link:       fmt.Sprintf("https://otx.alienvault.com/indicator/ip/%s", ipStr),
	}

	// Extract pulse names (up to 10)
	for i, pulse := range otxResp.PulseInfo.Pulses {
		if i >= 10 {
			break
		}
		a.result.Pulses = append(a.result.Pulses, OTXPulse{
			Name:     pulse.Name,
			Created:  pulse.Created,
			Tags:     pulse.Tags,
			Modified: pulse.Modified,
		})
	}

	// Extract referenced malware families
	seen := make(map[string]bool)
	for _, pulse := range otxResp.PulseInfo.Pulses {
		for _, tag := range pulse.Tags {
			lower := strings.ToLower(tag)
			if !seen[lower] {
				a.result.Tags = append(a.result.Tags, tag)
				seen[lower] = true
			}
			if len(a.result.Tags) >= 20 {
				break
			}
		}
	}

	return nil
}

func (a *AlienVaultOTX) Apply(result *Result) {
	if a.result != nil {
		result.AlienVault = a.result
	}
}

// --- OTX API response types ---

type otxGeneralResponse struct {
	Indicator   string       `json:"indicator"`
	Type        string       `json:"type"`
	Reputation  int          `json:"reputation"`
	CountryCode string       `json:"country_code"`
	ASN         string       `json:"asn"`
	PulseInfo   otxPulseInfo `json:"pulse_info"`
}

type otxPulseInfo struct {
	Count  int        `json:"count"`
	Pulses []otxPulse `json:"pulses"`
}

type otxPulse struct {
	Name     string   `json:"name"`
	Created  string   `json:"created"`
	Modified string   `json:"modified"`
	Tags     []string `json:"tags"`
}

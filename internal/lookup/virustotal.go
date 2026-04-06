package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

// VirusTotal queries the VirusTotal v3 API for IP intelligence.
type VirusTotal struct {
	apiKey string
	result *VirusTotalResult
}

func NewVirusTotal(apiKey string) *VirusTotal {
	return &VirusTotal{apiKey: apiKey}
}

func (v *VirusTotal) Name() string { return "virustotal" }

func (v *VirusTotal) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip.String())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-apikey", v.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("VirusTotal request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		v.result = &VirusTotalResult{Message: "IP not found in VirusTotal"}
		return nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("VirusTotal rate limit exceeded (free: 4 req/min)")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("VirusTotal returned status %d: %s", resp.StatusCode, string(body))
	}

	var vtResp vtResponse
	if err := json.Unmarshal(body, &vtResp); err != nil {
		return fmt.Errorf("VirusTotal parse error: %w", err)
	}

	attrs := vtResp.Data.Attributes
	v.result = &VirusTotalResult{
		Reputation:     attrs.Reputation,
		Malicious:      attrs.LastAnalysisStats.Malicious,
		Suspicious:     attrs.LastAnalysisStats.Suspicious,
		Harmless:       attrs.LastAnalysisStats.Harmless,
		Undetected:     attrs.LastAnalysisStats.Undetected,
		TotalEngines:   attrs.LastAnalysisStats.Malicious + attrs.LastAnalysisStats.Suspicious + attrs.LastAnalysisStats.Harmless + attrs.LastAnalysisStats.Undetected + attrs.LastAnalysisStats.Timeout,
		ASN:            attrs.ASN,
		ASOwner:        attrs.ASOwner,
		Country:        attrs.Country,
		Network:        attrs.Network,
		JARM:           attrs.JARM,
		VotesMalicious: attrs.TotalVotes.Malicious,
		VotesHarmless:  attrs.TotalVotes.Harmless,
		Link:           fmt.Sprintf("https://www.virustotal.com/gui/ip-address/%s", ip.String()),
	}

	// Extract top malicious engine names (up to 5)
	for name, engine := range attrs.LastAnalysisResults {
		if engine.Category == "malicious" || engine.Category == "suspicious" {
			v.result.FlaggedBy = append(v.result.FlaggedBy, name)
			if len(v.result.FlaggedBy) >= 5 {
				break
			}
		}
	}

	return nil
}

func (v *VirusTotal) Apply(result *Result) {
	result.VirusTotal = v.result
}

// --- VT API response types ---

type vtResponse struct {
	Data struct {
		Attributes vtAttributes `json:"attributes"`
	} `json:"data"`
}

type vtAttributes struct {
	Reputation          int                 `json:"reputation"`
	ASN                 int                 `json:"asn"`
	ASOwner             string              `json:"as_owner"`
	Country             string              `json:"country"`
	Network             string              `json:"network"`
	JARM                string              `json:"jarm"`
	LastAnalysisStats   vtAnalysisStats     `json:"last_analysis_stats"`
	LastAnalysisResults map[string]vtEngine `json:"last_analysis_results"`
	TotalVotes          vtVotes             `json:"total_votes"`
}

type vtAnalysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
}

type vtEngine struct {
	Category   string `json:"category"`
	EngineName string `json:"engine_name"`
	Method     string `json:"method"`
	Result     string `json:"result"`
}

type vtVotes struct {
	Malicious int `json:"malicious"`
	Harmless  int `json:"harmless"`
}

package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

// AbuseIPDB queries the AbuseIPDB API for abuse reports.
type AbuseIPDB struct {
	apiKey string
	result *AbuseIPDBResult
}

func NewAbuseIPDB(apiKey string) *AbuseIPDB {
	return &AbuseIPDB{apiKey: apiKey}
}

func (a *AbuseIPDB) Name() string { return "abuseipdb" }

func (a *AbuseIPDB) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip.String())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AbuseIPDB returned status %d: %s", resp.StatusCode, string(body))
	}

	var abuseResp abuseIPDBResponse
	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return fmt.Errorf("AbuseIPDB parse error: %w", err)
	}

	a.result = &AbuseIPDBResult{
		AbuseScore:     abuseResp.Data.AbuseConfidenceScore,
		TotalReports:   abuseResp.Data.TotalReports,
		CountryCode:    abuseResp.Data.CountryCode,
		ISP:            abuseResp.Data.ISP,
		Domain:         abuseResp.Data.Domain,
		UsageType:      abuseResp.Data.UsageType,
		IsWhitelisted:  abuseResp.Data.IsWhitelisted,
		LastReportedAt: abuseResp.Data.LastReportedAt,
	}

	return nil
}

func (a *AbuseIPDB) Apply(result *Result) {
	result.AbuseIPDB = a.result
}

type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		UsageType            string `json:"usageType"`
		TotalReports         int    `json:"totalReports"`
		LastReportedAt       string `json:"lastReportedAt"`
		IsWhitelisted        bool   `json:"isWhitelisted"`
	} `json:"data"`
}

package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// IPInfo queries the ipinfo.io API for IP context including VPN/proxy/Tor detection.
type IPInfo struct {
	apiKey string
	result *IPInfoResult
}

func NewIPInfo(apiKey string) *IPInfo {
	return &IPInfo{apiKey: apiKey}
}

func (i *IPInfo) Name() string { return "ipinfo" }

func (i *IPInfo) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://ipinfo.io/%s?token=%s", ip.String(), i.apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("IPinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("IPinfo rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("IPinfo returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var ipinfoResp ipinfoResponse
	if err := json.Unmarshal(body, &ipinfoResp); err != nil {
		return fmt.Errorf("IPinfo parse error: %w", err)
	}

	i.result = &IPInfoResult{
		Hostname: ipinfoResp.Hostname,
		City:     ipinfoResp.City,
		Region:   ipinfoResp.Region,
		Country:  ipinfoResp.Country,
		Loc:      ipinfoResp.Loc,
		Org:      ipinfoResp.Org,
		Timezone: ipinfoResp.Timezone,
		Postal:   ipinfoResp.Postal,
	}

	// Privacy/proxy detection (requires paid plan)
	if ipinfoResp.Privacy != nil {
		i.result.IsVPN = ipinfoResp.Privacy.VPN
		i.result.IsProxy = ipinfoResp.Privacy.Proxy
		i.result.IsTor = ipinfoResp.Privacy.Tor
		i.result.IsRelay = ipinfoResp.Privacy.Relay
		i.result.IsHosting = ipinfoResp.Privacy.Hosting
		i.result.PrivacyService = ipinfoResp.Privacy.Service
	}

	return nil
}

func (i *IPInfo) Apply(result *Result) {
	if i.result != nil {
		result.IPInfo = i.result
	}
}

// --- IPinfo API response types ---

type ipinfoResponse struct {
	IP       string         `json:"ip"`
	Hostname string         `json:"hostname"`
	City     string         `json:"city"`
	Region   string         `json:"region"`
	Country  string         `json:"country"`
	Loc      string         `json:"loc"`
	Org      string         `json:"org"`
	Timezone string         `json:"timezone"`
	Postal   string         `json:"postal"`
	Privacy  *ipinfoPrivacy `json:"privacy"`
}

type ipinfoPrivacy struct {
	VPN     bool   `json:"vpn"`
	Proxy   bool   `json:"proxy"`
	Tor     bool   `json:"tor"`
	Relay   bool   `json:"relay"`
	Hosting bool   `json:"hosting"`
	Service string `json:"service"`
}

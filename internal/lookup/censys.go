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

// Censys queries the Censys v2 API for host intelligence.
type Censys struct {
	apiID     string
	apiSecret string
	result    *CensysResult
}

func NewCensys(apiID, apiSecret string) *Censys {
	return &Censys{apiID: apiID, apiSecret: apiSecret}
}

func (c *Censys) Name() string { return "censys" }

func (c *Censys) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip.String())

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.apiID, c.apiSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Censys request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("Censys rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Censys returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var censysResp censysHostResponse
	if err := json.Unmarshal(body, &censysResp); err != nil {
		return fmt.Errorf("Censys parse error: %w", err)
	}

	host := censysResp.Result
	c.result = &CensysResult{
		Services:        len(host.Services),
		LastUpdated:     host.LastUpdatedAt,
		OperatingSystem: host.OperatingSystem.Product,
		ASN:             host.AutonomousSystem.ASN,
		ASName:          host.AutonomousSystem.Name,
		Country:         host.AutonomousSystem.CountryCode,
		Link:            fmt.Sprintf("https://search.censys.io/hosts/%s", ip.String()),
	}

	// Extract service details
	for _, svc := range host.Services {
		c.result.OpenPorts = append(c.result.OpenPorts, CensysService{
			Port:        svc.Port,
			Protocol:    svc.TransportProtocol,
			ServiceName: svc.ServiceName,
			Certificate: svc.TLS.Certificates.Leaf.Subject,
		})
	}

	return nil
}

func (c *Censys) Apply(result *Result) {
	if c.result != nil {
		result.Censys = c.result
	}
}

// --- Censys API response types ---

type censysHostResponse struct {
	Result struct {
		IP              string `json:"ip"`
		LastUpdatedAt   string `json:"last_updated_at"`
		OperatingSystem struct {
			Product string `json:"product"`
		} `json:"operating_system"`
		AutonomousSystem struct {
			ASN         int    `json:"asn"`
			Name        string `json:"name"`
			CountryCode string `json:"country_code"`
		} `json:"autonomous_system"`
		Services []struct {
			Port              int    `json:"port"`
			TransportProtocol string `json:"transport_protocol"`
			ServiceName       string `json:"service_name"`
			TLS               struct {
				Certificates struct {
					Leaf struct {
						Subject string `json:"subject_dn"`
					} `json:"leaf_data"`
				} `json:"certificates"`
			} `json:"tls"`
		} `json:"services"`
	} `json:"result"`
}

package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

// Shodan queries the Shodan API for host information.
type Shodan struct {
	apiKey string
	result *ShodanResult
}

func NewShodan(apiKey string) *Shodan {
	return &Shodan{apiKey: apiKey}
}

func (s *Shodan) Name() string { return "shodan" }

func (s *Shodan) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip.String(), s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Shodan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Shodan returned status %d: %s", resp.StatusCode, string(body))
	}

	var shodanResp shodanResponse
	if err := json.Unmarshal(body, &shodanResp); err != nil {
		return fmt.Errorf("Shodan parse error: %w", err)
	}

	s.result = &ShodanResult{
		OS:         shodanResp.OS,
		Ports:      shodanResp.Ports,
		Hostnames:  shodanResp.Hostnames,
		ISP:        shodanResp.ISP,
		Org:        shodanResp.Org,
		LastUpdate: shodanResp.LastUpdate,
	}

	if len(shodanResp.Vulns) > 0 {
		s.result.Vulns = shodanResp.Vulns
	}

	return nil
}

func (s *Shodan) Apply(result *Result) {
	result.Shodan = s.result
}

type shodanResponse struct {
	OS         string   `json:"os"`
	Ports      []int    `json:"ports"`
	Hostnames  []string `json:"hostnames"`
	ISP        string   `json:"isp"`
	Org        string   `json:"org"`
	Vulns      []string `json:"vulns"`
	LastUpdate string   `json:"last_update"`
}

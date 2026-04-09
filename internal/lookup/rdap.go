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

// rdapEndpoint defines an RIR's RDAP service.
type rdapEndpoint struct {
	Name   string // RIR name (e.g., "ARIN")
	Region string // coverage region
	URL    string // RDAP base URL (append IP)
}

// rdapFallbackEndpoints lists all five RIR RDAP services for fallback.
var rdapFallbackEndpoints = []rdapEndpoint{
	{Name: "ARIN", Region: "North America", URL: "https://rdap.arin.net/registry/ip/"},
	{Name: "RIPE", Region: "Europe / Middle East", URL: "https://rdap.db.ripe.net/ip/"},
	{Name: "APNIC", Region: "Asia Pacific", URL: "https://rdap.apnic.net/ip/"},
	{Name: "LACNIC", Region: "Latin Am. / Caribbean", URL: "https://rdap.lacnic.net/rdap/ip/"},
	{Name: "AFRINIC", Region: "Africa", URL: "https://rdap.afrinic.net/rdap/ip/"},
}

// RDAP queries the RDAP service for IP registration info.
// Uses the IANA RDAP bootstrap (rdap.org) which auto-redirects to the correct
// RIR. Falls back to trying each RIR directly if the bootstrap is unavailable.
type RDAP struct {
	result *RDAPResult
}

func NewRDAP() *RDAP {
	return &RDAP{}
}

func (r *RDAP) Name() string { return "rdap" }

func (r *RDAP) Lookup(ctx context.Context, ip net.IP) error {
	ipStr := ip.String()

	// Build an HTTP client that follows redirects (IANA bootstrap redirects to the correct RIR).
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	// Primary: IANA RDAP bootstrap — auto-redirects to the correct RIR.
	body, source, err := r.queryRDAP(ctx, client, "https://rdap.org/ip/"+ipStr, "IANA bootstrap")
	if err != nil {
		// Fallback: try each RIR endpoint directly.
		for _, ep := range rdapFallbackEndpoints {
			body, source, err = r.queryRDAP(ctx, client, ep.URL+ipStr, ep.Name)
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("RDAP: all endpoints failed for %s: %w", ipStr, err)
		}
	}

	var rdapResp rdapResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return fmt.Errorf("RDAP parse error: %w", err)
	}

	r.result = &RDAPResult{
		Name:      rdapResp.Name,
		Handle:    rdapResp.Handle,
		StartAddr: rdapResp.StartAddress,
		EndAddr:   rdapResp.EndAddress,
		Type:      rdapResp.Type,
		Source:    source,
	}

	if len(rdapResp.CIDR0Cidrs) > 0 {
		cidrs := make([]string, 0, len(rdapResp.CIDR0Cidrs))
		for _, c := range rdapResp.CIDR0Cidrs {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", c.V4Prefix+c.V6Prefix, c.Length))
		}
		r.result.CIDR = strings.Join(cidrs, ", ")
	}

	for _, entity := range rdapResp.Entities {
		if entity.VCardArray != nil && len(entity.VCardArray) > 1 {
			if props, ok := entity.VCardArray[1].([]interface{}); ok {
				for _, prop := range props {
					if arr, ok := prop.([]interface{}); ok && len(arr) >= 4 {
						if arr[0] == "fn" {
							r.result.OrgName = fmt.Sprintf("%v", arr[3])
						}
					}
				}
			}
		}

		for _, role := range entity.Roles {
			if role == "abuse" {
				r.result.AbuseEmail = extractAbuseEmail(entity)
			}
		}

		for _, nested := range entity.Entities {
			for _, role := range nested.Roles {
				if role == "abuse" {
					r.result.AbuseEmail = extractAbuseEmail(nested)
				}
			}
		}
	}

	for _, event := range rdapResp.Events {
		if event.Action == "last changed" {
			r.result.UpdatedAt = event.Date
		}
	}

	if rdapResp.Country != "" {
		r.result.Country = rdapResp.Country
	}

	// Try to detect the RIR source from the RDAP port43 or links if bootstrap was used.
	if r.result.Source == "IANA bootstrap" {
		if detected := detectRIRFromResponse(rdapResp); detected != "" {
			r.result.Source = detected
		}
	}

	return nil
}

// queryRDAP performs a single RDAP HTTP request and returns the body on success.
func (r *RDAP) queryRDAP(ctx context.Context, client *http.Client, url, source string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("status %d from %s", resp.StatusCode, source)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	return body, source, nil
}

// detectRIRFromResponse infers the RIR name from RDAP response metadata.
func detectRIRFromResponse(resp rdapResponse) string {
	// Check port43 field (whois server).
	port43Lower := strings.ToLower(resp.Port43)
	for _, kv := range []struct {
		substr string
		rir    string
	}{
		{"arin", "ARIN"},
		{"ripe", "RIPE"},
		{"apnic", "APNIC"},
		{"lacnic", "LACNIC"},
		{"afrinic", "AFRINIC"},
	} {
		if strings.Contains(port43Lower, kv.substr) {
			return kv.rir
		}
	}

	// Check links for RIR domain hints.
	for _, link := range resp.Links {
		href := strings.ToLower(link.Href)
		for _, kv := range []struct {
			substr string
			rir    string
		}{
			{"arin.net", "ARIN"},
			{"ripe.net", "RIPE"},
			{"apnic.net", "APNIC"},
			{"lacnic.net", "LACNIC"},
			{"afrinic.net", "AFRINIC"},
		} {
			if strings.Contains(href, kv.substr) {
				return kv.rir
			}
		}
	}
	return ""
}

func (r *RDAP) Apply(result *Result) {
	result.RDAP = r.result
}

type rdapResponse struct {
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	Type         string       `json:"type"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Country      string       `json:"country"`
	Port43       string       `json:"port43"`
	Entities     []rdapEntity `json:"entities"`
	Events       []rdapEvent  `json:"events"`
	CIDR0Cidrs   []rdapCIDR   `json:"cidr0_cidrs"`
	Links        []rdapLink   `json:"links"`
}

type rdapEntity struct {
	Handle     string        `json:"handle"`
	Roles      []string      `json:"roles"`
	VCardArray []interface{} `json:"vcardArray"`
	Entities   []rdapEntity  `json:"entities"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapCIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

type rdapLink struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
	Type string `json:"type"`
}

func extractAbuseEmail(entity rdapEntity) string {
	if entity.VCardArray == nil || len(entity.VCardArray) < 2 {
		return ""
	}
	props, ok := entity.VCardArray[1].([]interface{})
	if !ok {
		return ""
	}
	for _, prop := range props {
		arr, ok := prop.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}
		if arr[0] == "email" {
			return fmt.Sprintf("%v", arr[3])
		}
	}
	return ""
}

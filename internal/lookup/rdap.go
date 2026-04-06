package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// RDAP queries the RDAP service for IP registration info.
type RDAP struct {
	result *RDAPResult
}

func NewRDAP() *RDAP {
	return &RDAP{}
}

func (r *RDAP) Name() string { return "rdap" }

func (r *RDAP) Lookup(ctx context.Context, ip net.IP) error {
	url := fmt.Sprintf("https://rdap.arin.net/registry/ip/%s", ip.String())

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("RDAP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RDAP returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
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

	return nil
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
	Entities     []rdapEntity `json:"entities"`
	Events       []rdapEvent  `json:"events"`
	CIDR0Cidrs   []rdapCIDR   `json:"cidr0_cidrs"`
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

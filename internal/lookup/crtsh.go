package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
)

// CrtSh queries the Certificate Transparency log via crt.sh.
type CrtSh struct {
	results []CertResult
}

func NewCrtSh() *CrtSh {
	return &CrtSh{}
}

func (c *CrtSh) Name() string { return "crt_sh" }

func (c *CrtSh) Lookup(ctx context.Context, ip net.IP) error {
	resolver := net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return nil
	}

	hostname := names[0]
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	domain := extractBaseDomain(hostname)

	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var crtEntries []crtShEntry
	if err := json.Unmarshal(body, &crtEntries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	for _, entry := range crtEntries {
		if seen[entry.CommonName] {
			continue
		}
		seen[entry.CommonName] = true
		c.results = append(c.results, CertResult{
			CommonName: entry.CommonName,
			Issuer:     entry.IssuerName,
			NotBefore:  entry.NotBefore,
			NotAfter:   entry.NotAfter,
			SANs:       entry.NameValue,
		})
		if len(c.results) >= 10 {
			break
		}
	}

	return nil
}

func (c *CrtSh) Apply(result *Result) {
	result.Certificates = c.results
}

type crtShEntry struct {
	ID         int    `json:"id"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

func extractBaseDomain(hostname string) string {
	parts := splitDomain(hostname)
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return hostname
}

func splitDomain(s string) []string {
	var parts []string
	current := ""
	for _, c := range s {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

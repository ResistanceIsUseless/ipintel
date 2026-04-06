package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ASNLookup resolves ASN information using Team Cymru's DNS-based service.
// No API key required. Works by querying <reversed-ip>.origin.asn.cymru.com for
// ASN/prefix data, then AS<number>.asn.cymru.com for AS name/country.
type ASNLookup struct {
	result *ASNResult
}

func NewASNLookup() *ASNLookup {
	return &ASNLookup{}
}

func (a *ASNLookup) Name() string { return "asn" }

func (a *ASNLookup) Lookup(ctx context.Context, ip net.IP) error {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Step 1: Query origin.asn.cymru.com for ASN and prefix
	// Format: <reversed-ip>.origin.asn.cymru.com (IPv4)
	//         or <reversed-nibbles>.origin6.asn.cymru.com (IPv6)
	originName := buildCymruOriginName(ip)
	if originName == "" {
		return nil
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(originName), dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil || r == nil || len(r.Answer) == 0 {
		return nil // non-fatal
	}

	// Parse response: "ASN | Prefix | CC | RIR | Date"
	// Example: "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
	var asnNum, prefix, cc, rir string
	for _, rr := range r.Answer {
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
			parts := strings.Split(txt.Txt[0], "|")
			if len(parts) >= 3 {
				asnNum = strings.TrimSpace(parts[0])
				prefix = strings.TrimSpace(parts[1])
				cc = strings.TrimSpace(parts[2])
			}
			if len(parts) >= 4 {
				rir = strings.TrimSpace(parts[3])
			}
			break
		}
	}

	if asnNum == "" {
		return nil
	}

	a.result = &ASNResult{
		Number:  "AS" + asnNum,
		CIDR:    prefix,
		Country: cc,
		RIR:     rir,
	}

	// Step 2: Query AS<number>.asn.cymru.com for AS name
	asNameQuery := fmt.Sprintf("AS%s.asn.cymru.com.", asnNum)
	m2 := new(dns.Msg)
	m2.SetQuestion(asNameQuery, dns.TypeTXT)
	m2.RecursionDesired = true

	r2, _, err := c.ExchangeContext(ctx, m2, "8.8.8.8:53")
	if err == nil && r2 != nil {
		for _, rr := range r2.Answer {
			if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
				// Format: "ASN | CC | RIR | Date | AS Name"
				parts := strings.Split(txt.Txt[0], "|")
				if len(parts) >= 5 {
					a.result.Name = strings.TrimSpace(parts[4])
				}
				break
			}
		}
	}

	return nil
}

func (a *ASNLookup) Apply(result *Result) {
	if a.result != nil {
		result.ASN = a.result
	}
}

// buildCymruOriginName constructs the Team Cymru DNS query name for an IP.
func buildCymruOriginName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com.", v4[3], v4[2], v4[1], v4[0])
	}

	full := ip.To16()
	if full == nil {
		return ""
	}
	var sb strings.Builder
	for i := len(full) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", full[i]&0x0f, (full[i]>>4)&0x0f))
	}
	sb.WriteString("origin6.asn.cymru.com.")
	return sb.String()
}

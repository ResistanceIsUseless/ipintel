package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ForwardDNSRecon performs a full DNS recon on hostnames discovered via PTR records.
// Queries A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV records.
type ForwardDNSRecon struct {
	result *ForwardDNSResult
}

func NewForwardDNSRecon() *ForwardDNSRecon {
	return &ForwardDNSRecon{}
}

func (f *ForwardDNSRecon) Name() string { return "forward_dns" }

func (f *ForwardDNSRecon) Lookup(ctx context.Context, ip net.IP) error {
	// First resolve PTR to get hostnames
	resolver := &net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return nil // no PTR, nothing to recon
	}

	// Use the first PTR hostname (most authoritative)
	hostname := strings.TrimSuffix(names[0], ".")
	if hostname == "" {
		return nil
	}

	// Extract the domain portion for NS/SOA/MX/TXT/CAA queries
	// For hostnames like "ec2-1-2-3-4.compute.amazonaws.com", we query the hostname itself.
	// For record types that apply to domains (MX, NS, SOA, CAA, TXT), we also try the parent domain.
	domain := extractDomain(hostname)

	f.result = &ForwardDNSResult{
		Hostname: hostname,
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second
	server := "8.8.8.8:53"

	// Query all record types
	f.result.A = queryRecords(ctx, c, server, hostname, dns.TypeA)
	f.result.AAAA = queryRecords(ctx, c, server, hostname, dns.TypeAAAA)
	f.result.CNAME = queryRecords(ctx, c, server, hostname, dns.TypeCNAME)

	// For domain-level records, query the parent domain if different from hostname
	queryTarget := hostname
	if domain != "" && domain != hostname {
		queryTarget = domain
	}

	f.result.MX = queryRecords(ctx, c, server, queryTarget, dns.TypeMX)
	f.result.NS = queryRecords(ctx, c, server, queryTarget, dns.TypeNS)
	f.result.TXT = queryRecords(ctx, c, server, queryTarget, dns.TypeTXT)
	f.result.SOA = queryRecords(ctx, c, server, queryTarget, dns.TypeSOA)
	f.result.CAA = queryRecords(ctx, c, server, queryTarget, dns.TypeCAA)
	f.result.SRV = queryRecords(ctx, c, server, queryTarget, dns.TypeSRV)

	// If we got absolutely nothing useful, don't apply
	if f.isEmpty() {
		f.result = nil
	}

	return nil
}

func (f *ForwardDNSRecon) Apply(result *Result) {
	if f.result != nil {
		result.ForwardDNS = f.result
	}
}

func (f *ForwardDNSRecon) isEmpty() bool {
	r := f.result
	return r == nil || (len(r.A) == 0 && len(r.AAAA) == 0 && len(r.CNAME) == 0 &&
		len(r.MX) == 0 && len(r.NS) == 0 && len(r.TXT) == 0 &&
		len(r.SOA) == 0 && len(r.CAA) == 0 && len(r.SRV) == 0)
}

// queryRecords performs a DNS query and returns human-readable answer strings.
func queryRecords(ctx context.Context, c *dns.Client, server, name string, qtype uint16) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil || r == nil || len(r.Answer) == 0 {
		return nil
	}

	var results []string
	for _, rr := range r.Answer {
		val := formatRR(rr)
		if val != "" {
			results = append(results, val)
		}
	}
	return results
}

// formatRR extracts the data portion of a DNS RR into a readable string.
func formatRR(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.TXT:
		return strings.Join(v.Txt, " ")
	case *dns.SOA:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			strings.TrimSuffix(v.Ns, "."),
			strings.TrimSuffix(v.Mbox, "."),
			v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.CAA:
		return fmt.Sprintf("%d %s \"%s\"", v.Flag, v.Tag, v.Value)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	default:
		// Fallback: use String() and strip the header
		s := rr.String()
		// Find tab-separated fields, return data after header
		parts := strings.SplitN(s, "\t", 5)
		if len(parts) == 5 {
			return parts[4]
		}
		return s
	}
}

// extractDomain extracts the registrable domain from a hostname.
// Simple heuristic: take the last two labels (or three for known CCTLDs).
func extractDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}

	// Common two-part TLDs
	twoPartTLDs := map[string]bool{
		"co.uk": true, "com.au": true, "co.jp": true, "co.nz": true,
		"com.br": true, "co.za": true, "com.cn": true, "org.uk": true,
		"ac.uk": true, "gov.uk": true, "com.sg": true, "com.hk": true,
	}

	if len(parts) >= 3 {
		lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if twoPartTLDs[lastTwo] {
			if len(parts) >= 4 {
				return strings.Join(parts[len(parts)-3:], ".")
			}
			return hostname
		}
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

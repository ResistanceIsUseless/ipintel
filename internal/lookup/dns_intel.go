package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSIntel performs deep DNS analysis: SOA/NS discovery, FCrDNS, auth NS comparison, AXFR, trace.
type DNSIntel struct {
	result *DNSIntelResult
}

func NewDNSIntel() *DNSIntel {
	return &DNSIntel{}
}

func (d *DNSIntel) Name() string { return "dns_intel" }

func (d *DNSIntel) Lookup(ctx context.Context, ip net.IP) error {
	d.result = &DNSIntelResult{}

	// Build the reverse zone name (e.g., 57.117.137.in-addr.arpa)
	reverseZone := buildReverseZone(ip)
	d.result.ReverseZone = reverseZone

	// Build the full PTR name for this specific IP
	ptrName := buildPTRName(ip)

	resolver := &net.Resolver{}

	// --- Step 1: Get PTR from system recursive resolver ---
	recursivePTR, _ := resolver.LookupAddr(ctx, ip.String())
	d.result.RecursivePTR = cleanHostnames(recursivePTR)

	// --- Step 2: Find authoritative NS for the reverse zone ---
	ns, soaPrimary, soaEmail := discoverAuthNS(ctx, reverseZone)
	d.result.Nameservers = ns
	d.result.SOAPrimary = soaPrimary
	d.result.SOAEmail = soaEmail

	// --- Step 3: Query authoritative NS directly for PTR ---
	if len(ns) > 0 {
		authPTR := queryAuthPTR(ctx, ns[0], ptrName)
		d.result.AuthPTR = cleanHostnames(authPTR)

		// Compare results
		d.result.PTRMismatch = !slicesEqual(d.result.RecursivePTR, d.result.AuthPTR)
	}

	// --- Step 4: Forward-Confirmed reverse DNS (FCrDNS) ---
	allPTR := d.result.RecursivePTR
	if len(allPTR) == 0 {
		allPTR = d.result.AuthPTR
	}

	for _, ptr := range allPTR {
		entry := FCrDNSEntry{PTR: ptr}

		addrs, err := resolver.LookupHost(ctx, ptr)
		if err == nil && len(addrs) > 0 {
			entry.ForwardIP = strings.Join(addrs, ", ")
			for _, addr := range addrs {
				if addr == ip.String() {
					entry.Confirmed = true
					break
				}
			}
		}

		d.result.FCrDNS = append(d.result.FCrDNS, entry)
	}

	// --- Step 5: AXFR (zone transfer) attempt ---
	if len(ns) > 0 {
		d.result.AXFRRecords, d.result.AXFRSuccess = attemptAXFR(ctx, ns[0], reverseZone)
	}

	// --- Step 6: DNS trace (delegation chain from root) ---
	d.result.Trace = dnsTrace(ctx, ptrName)

	return nil
}

func (d *DNSIntel) Apply(result *Result) {
	result.DNSIntel = d.result
}

// buildReverseZone builds the in-addr.arpa or ip6.arpa zone for the IP (/24 boundary for IPv4).
func buildReverseZone(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.in-addr.arpa.", v4[2], v4[1], v4[0])
	}

	full := ip.To16()
	if full == nil {
		return ""
	}
	var sb strings.Builder
	for i := len(full) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", full[i]&0x0f, (full[i]>>4)&0x0f))
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// buildPTRName builds the full reverse DNS name for an IP (e.g., "4.3.2.1.in-addr.arpa.").
func buildPTRName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}

	full := ip.To16()
	if full == nil {
		return ""
	}
	var sb strings.Builder
	for i := len(full) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", full[i]&0x0f, (full[i]>>4)&0x0f))
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// discoverAuthNS finds NS and SOA records for a reverse zone using miekg/dns.
func discoverAuthNS(ctx context.Context, zone string) (ns []string, soaPrimary, soaEmail string) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Walk up the zone to find NS records
	current := dns.Fqdn(zone)
	for attempts := 0; attempts < 5; attempts++ {
		m := new(dns.Msg)
		m.SetQuestion(current, dns.TypeNS)
		m.RecursionDesired = true

		r, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53")
		if err == nil && r != nil && len(r.Answer) > 0 {
			for _, rr := range r.Answer {
				if nsRR, ok := rr.(*dns.NS); ok {
					host := strings.TrimSuffix(nsRR.Ns, ".")
					if host != "" {
						ns = append(ns, host)
					}
				}
			}
			if len(ns) > 0 {
				break
			}
		}

		// Walk up one label
		idx := strings.Index(current, ".")
		if idx < 0 || current[idx+1:] == "" {
			break
		}
		current = current[idx+1:]
	}

	// SOA query on the zone
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.RecursionDesired = true
	r, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err == nil && r != nil {
		// Check answer section first, then authority
		for _, rr := range append(r.Answer, r.Ns...) {
			if soa, ok := rr.(*dns.SOA); ok {
				soaPrimary = strings.TrimSuffix(soa.Ns, ".")
				soaEmail = strings.TrimSuffix(soa.Mbox, ".")
				// Convert DNS email format (first dot -> @)
				if idx := strings.Index(soaEmail, "."); idx > 0 {
					soaEmail = soaEmail[:idx] + "@" + soaEmail[idx+1:]
				}
				break
			}
		}
	}

	return
}

// queryAuthPTR queries a specific nameserver for PTR records using miekg/dns.
func queryAuthPTR(ctx context.Context, nsHost string, ptrName string) []string {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(ptrName), dns.TypePTR)
	m.RecursionDesired = false // direct authoritative query

	nsAddr := nsHost + ":53"
	r, _, err := c.ExchangeContext(ctx, m, nsAddr)
	if err != nil || r == nil {
		return nil
	}

	var names []string
	for _, rr := range r.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			names = append(names, ptr.Ptr)
		}
	}
	return names
}

// attemptAXFR tries a zone transfer against the authoritative NS.
func attemptAXFR(ctx context.Context, nsHost string, zone string) (records []string, success bool) {
	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))

	nsAddr := nsHost + ":53"
	ch, err := t.In(m, nsAddr)
	if err != nil {
		return nil, false
	}

	// Read with a limit to avoid flooding
	maxRecords := 500
	for envelope := range ch {
		if envelope.Error != nil {
			if len(records) == 0 {
				return nil, false
			}
			break
		}
		for _, rr := range envelope.RR {
			if len(records) >= maxRecords {
				records = append(records, fmt.Sprintf("... truncated (>%d records)", maxRecords))
				// Drain the channel
				for range ch {
				}
				return records, true
			}
			records = append(records, rr.String())
		}
	}

	return records, len(records) > 0
}

// dnsTrace performs iterative resolution from root servers, recording each delegation hop.
func dnsTrace(ctx context.Context, name string) []TraceHop {
	var hops []TraceHop
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	// Start from a root server
	rootServers := []string{"198.41.0.4:53", "199.9.14.201:53", "192.33.4.12:53"}
	currentServer := rootServers[0]
	qname := dns.Fqdn(name)
	qtype := dns.TypePTR

	seen := make(map[string]bool)
	maxHops := 20

	for i := 0; i < maxHops; i++ {
		if seen[currentServer] {
			break
		}
		seen[currentServer] = true

		m := new(dns.Msg)
		m.SetQuestion(qname, qtype)
		m.RecursionDesired = false

		r, _, err := c.ExchangeContext(ctx, m, currentServer)
		if err != nil {
			hops = append(hops, TraceHop{
				Server: currentServer,
				Query:  qname,
				Type:   dns.TypeToString[qtype],
				Rcode:  "ERROR: " + err.Error(),
			})
			break
		}

		hop := TraceHop{
			Server: currentServer,
			Query:  qname,
			Type:   dns.TypeToString[qtype],
			Rcode:  dns.RcodeToString[r.Rcode],
		}

		// Collect answers
		for _, rr := range r.Answer {
			hop.Answers = append(hop.Answers, rr.String())
		}

		hops = append(hops, hop)

		// If we got an answer, we're done
		if len(r.Answer) > 0 {
			break
		}

		// Follow delegation (NS in authority section)
		var nextNS string
		for _, rr := range r.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nextNS = ns.Ns
				break
			}
		}
		if nextNS == "" {
			break
		}

		// Resolve the NS name to an IP using the additional section first
		nextAddr := ""
		for _, rr := range r.Extra {
			if a, ok := rr.(*dns.A); ok && a.Hdr.Name == nextNS {
				nextAddr = a.A.String() + ":53"
				break
			}
		}
		// Fallback: resolve the NS name
		if nextAddr == "" {
			ips, err := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(nextNS, "."))
			if err != nil || len(ips) == 0 {
				break
			}
			nextAddr = ips[0] + ":53"
		}

		currentServer = nextAddr
	}

	return hops
}

// cleanHostnames strips trailing dots from DNS names.
func cleanHostnames(names []string) []string {
	cleaned := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if name != "" {
			cleaned = append(cleaned, name)
		}
	}
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

// slicesEqual checks if two string slices have the same elements (order-independent).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]bool)
	for _, v := range a {
		aMap[v] = true
	}
	for _, v := range b {
		if !aMap[v] {
			return false
		}
	}
	return true
}

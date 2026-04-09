package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/mgriffiths/ipintel/internal/lookup"
)

// Format controls the output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

// Color palette
var (
	colorPrimary   = lipgloss.Color("#7C3AED") // purple
	colorSecondary = lipgloss.Color("#06B6D4") // cyan
	colorMuted     = lipgloss.Color("#6B7280") // gray
	colorSuccess   = lipgloss.Color("#10B981") // green
	colorDanger    = lipgloss.Color("#EF4444") // red
	colorWarning   = lipgloss.Color("#F59E0B") // amber
	colorLabel     = lipgloss.Color("#94A3B8") // slate
	colorValue     = lipgloss.Color("#E2E8F0") // light gray

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			PaddingLeft(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			PaddingLeft(1)

	sectionHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorSecondary).
				PaddingLeft(1).
				PaddingTop(1)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorLabel).
			Width(20).
			Align(lipgloss.Right).
			PaddingRight(1)

	valueStyle = lipgloss.NewStyle().
			Foreground(colorValue)

	dimStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Italic(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(colorDanger)

	successBadge = lipgloss.NewStyle().
			Foreground(colorSuccess).
			Bold(true)

	dangerBadge = lipgloss.NewStyle().
			Foreground(colorDanger).
			Bold(true)

	warnBadge = lipgloss.NewStyle().
			Foreground(colorWarning).
			Bold(true)

	cloudBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	borderStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(0, 1).
			MarginBottom(1)
)

// Render writes the result in the requested format.
func Render(w io.Writer, result *lookup.Result, format Format) error {
	switch format {
	case FormatJSON:
		return renderJSON(w, result)
	default:
		return renderStyled(w, result)
	}
}

func renderJSON(w io.Writer, result *lookup.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func renderStyled(w io.Writer, result *lookup.Result) error {
	var sb strings.Builder

	// Header box
	headerLines := []string{
		titleStyle.Render("IP Intelligence Report"),
		lipgloss.NewStyle().Bold(true).Foreground(colorValue).PaddingLeft(1).Render(result.IP),
	}
	if result.IsPrivate {
		headerLines = append(headerLines, lipgloss.NewStyle().PaddingLeft(1).Render(
			warnBadge.Render("PRIVATE IP")+" "+dimStyle.Render("(cloud tenant lookups only)"),
		))
	}
	headerLines = append(headerLines, subtitleStyle.Render(result.Timestamp.Format("2006-01-02 15:04:05 UTC")))

	header := lipgloss.JoinVertical(lipgloss.Left, headerLines...)
	sb.WriteString(boxStyle.Render(header))
	sb.WriteString("\n")

	// --- Network Identity ---

	// Reverse DNS
	sb.WriteString(renderReverseDNS(result))

	// ASN
	if result.ASN != nil {
		sb.WriteString(renderASN(result.ASN))
	}

	// RDAP
	if result.RDAP != nil {
		sb.WriteString(renderRDAP(result.RDAP))
	}

	// Cloud Provider
	if result.Cloud != nil {
		sb.WriteString(renderCloud(result.Cloud))
	}

	// CDN / WAF
	if result.CDN != nil && result.CDN.Detected {
		sb.WriteString(renderCDN(result.CDN))
	}

	// --- DNS Deep Dive ---

	// DNS Intelligence
	if result.DNSIntel != nil {
		sb.WriteString(renderDNSIntel(result.DNSIntel))
	}

	// Forward DNS Recon
	if result.ForwardDNS != nil {
		sb.WriteString(renderForwardDNS(result.ForwardDNS))
	}

	// --- Infrastructure ---

	// Port Scan
	if result.Ports != nil {
		sb.WriteString(renderPortScan(result.Ports))
	}

	// Web / TLS Intel
	if result.WebIntel != nil {
		sb.WriteString(renderWebIntel(result.WebIntel))
	}

	// --- Threat Intelligence ---

	// GreyNoise
	if result.GreyNoise != nil {
		sb.WriteString(renderGreyNoise(result.GreyNoise))
	}

	// AbuseIPDB
	if result.AbuseIPDB != nil {
		sb.WriteString(renderAbuseIPDB(result.AbuseIPDB))
	}

	// Shodan
	if result.Shodan != nil {
		sb.WriteString(renderShodan(result.Shodan))
	}

	// VirusTotal
	if result.VirusTotal != nil {
		sb.WriteString(renderVirusTotal(result.VirusTotal))
	}

	// Certificates
	if len(result.Certificates) > 0 {
		sb.WriteString(renderCerts(result.Certificates))
	}

	// --- Cloud Tenant Lookups ---

	// Azure Tenant
	if result.AzureTenant != nil {
		sb.WriteString(renderAzureTenant(result.AzureTenant))
	}

	// AWS Tenant
	if result.AWSTenant != nil {
		sb.WriteString(renderAWSTenant(result.AWSTenant))
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString(renderErrors(result.Errors))
	}

	sb.WriteString("\n")
	fmt.Fprint(w, sb.String())
	return nil
}

// --- Section Renderers ---

func renderReverseDNS(result *lookup.Result) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Reverse DNS"))
	sb.WriteString("\n")
	if len(result.ReverseDNS) > 0 {
		for _, name := range result.ReverseDNS {
			sb.WriteString(fieldRow("PTR", name))
		}
	} else {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No PTR records found")))
		sb.WriteString("\n")
	}
	return sb.String()
}

func renderRDAP(r *lookup.RDAPResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("RDAP / Registration"))
	sb.WriteString("\n")

	rows := [][]string{}
	addRow := func(label, value string) {
		if value != "" {
			rows = append(rows, []string{label, value})
		}
	}

	addRow("Network", r.Name)
	addRow("Handle", r.Handle)
	addRow("CIDR", r.CIDR)
	if r.StartAddr != "" && r.EndAddr != "" {
		addRow("Range", fmt.Sprintf("%s - %s", r.StartAddr, r.EndAddr))
	}
	addRow("Organization", r.OrgName)
	addRow("Country", r.Country)
	addRow("Type", r.Type)
	addRow("RIR", r.Source)
	addRow("Abuse Contact", r.AbuseEmail)
	addRow("Last Updated", r.UpdatedAt)

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderCloud(c *lookup.CloudResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Cloud Provider"))
	sb.WriteString("\n")

	badge := cloudBadge
	switch strings.ToLower(c.Provider) {
	case "aws":
		badge = badge.Background(lipgloss.Color("#FF9900"))
	case "azure":
		badge = badge.Background(lipgloss.Color("#0078D4"))
	case "gcp":
		badge = badge.Background(lipgloss.Color("#4285F4"))
	default:
		badge = badge.Background(lipgloss.Color("#6B7280"))
	}

	sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(badge.Render(c.Provider)))
	sb.WriteString("\n\n")

	rows := [][]string{}
	if c.Service != "" {
		rows = append(rows, []string{"Service", c.Service})
	}
	if c.Region != "" {
		rows = append(rows, []string{"Region", c.Region})
	}
	if c.NetworkCIDR != "" {
		rows = append(rows, []string{"Network", c.NetworkCIDR})
	}

	if len(rows) > 0 {
		sb.WriteString(renderKVTable(rows))
	}
	return sb.String()
}

func renderGreyNoise(g *lookup.GreyNoiseResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("GreyNoise"))
	sb.WriteString("\n")

	if !g.Seen {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("Not observed by GreyNoise")))
		sb.WriteString("\n")
		return sb.String()
	}

	var classBadge string
	switch g.Classification {
	case "benign":
		classBadge = successBadge.Render("BENIGN")
	case "malicious":
		classBadge = dangerBadge.Render("MALICIOUS")
	default:
		classBadge = warnBadge.Render(strings.ToUpper(g.Classification))
	}
	sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(classBadge))
	sb.WriteString("\n\n")

	rows := [][]string{}
	if g.Name != "" {
		rows = append(rows, []string{"Name", g.Name})
	}
	rows = append(rows, []string{"Noise", fmt.Sprintf("%v", g.Noise)})
	rows = append(rows, []string{"RIOT (Benign Svc)", fmt.Sprintf("%v", g.RIOT)})
	if g.LastSeen != "" {
		rows = append(rows, []string{"Last Seen", g.LastSeen})
	}
	if g.Link != "" {
		rows = append(rows, []string{"Link", g.Link})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderAbuseIPDB(a *lookup.AbuseIPDBResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("AbuseIPDB"))
	sb.WriteString("\n")

	var scoreBadge string
	switch {
	case a.AbuseScore >= 75:
		scoreBadge = dangerBadge.Render(fmt.Sprintf("%d%%", a.AbuseScore))
	case a.AbuseScore >= 25:
		scoreBadge = warnBadge.Render(fmt.Sprintf("%d%%", a.AbuseScore))
	default:
		scoreBadge = successBadge.Render(fmt.Sprintf("%d%%", a.AbuseScore))
	}

	rows := [][]string{
		{"Abuse Score", scoreBadge},
		{"Total Reports", fmt.Sprintf("%d", a.TotalReports)},
	}
	if a.CountryCode != "" {
		rows = append(rows, []string{"Country", a.CountryCode})
	}
	if a.ISP != "" {
		rows = append(rows, []string{"ISP", a.ISP})
	}
	if a.Domain != "" {
		rows = append(rows, []string{"Domain", a.Domain})
	}
	if a.UsageType != "" {
		rows = append(rows, []string{"Usage Type", a.UsageType})
	}
	if a.LastReportedAt != "" {
		rows = append(rows, []string{"Last Reported", a.LastReportedAt})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderShodan(s *lookup.ShodanResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Shodan"))
	sb.WriteString("\n")

	rows := [][]string{}
	if s.OS != "" {
		rows = append(rows, []string{"OS", s.OS})
	}
	if s.ISP != "" {
		rows = append(rows, []string{"ISP", s.ISP})
	}
	if s.Org != "" {
		rows = append(rows, []string{"Organization", s.Org})
	}
	if len(s.Ports) > 0 {
		ports := make([]string, len(s.Ports))
		for i, p := range s.Ports {
			ports[i] = fmt.Sprintf("%d", p)
		}
		rows = append(rows, []string{"Open Ports", strings.Join(ports, ", ")})
	}
	if len(s.Hostnames) > 0 {
		rows = append(rows, []string{"Hostnames", strings.Join(s.Hostnames, ", ")})
	}
	if len(s.Vulns) > 0 {
		rows = append(rows, []string{"Vulns", dangerBadge.Render(strings.Join(s.Vulns, ", "))})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderCerts(certs []lookup.CertResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Certificate Transparency"))
	sb.WriteString("\n")

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(borderStyle).
		Headers("Common Name", "Issuer", "Valid From", "Valid Until").
		StyleFunc(func(row, col int) lipgloss.Style {
			s := lipgloss.NewStyle().Padding(0, 1)
			if row == table.HeaderRow {
				return s.Foreground(colorSecondary).Bold(true)
			}
			if row%2 == 0 {
				return s.Foreground(colorValue)
			}
			return s.Foreground(colorLabel)
		}).
		Width(80)

	for _, cert := range certs {
		t.Row(cert.CommonName, cert.Issuer, cert.NotBefore, cert.NotAfter)
	}

	sb.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(t.Render()))
	sb.WriteString("\n")
	return sb.String()
}

func renderErrors(errors []lookup.ProviderError) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Foreground(colorWarning).Render("Provider Errors"))
	sb.WriteString("\n")

	for _, e := range errors {
		line := fmt.Sprintf("  %s %s",
			errorStyle.Bold(true).Render(e.Provider+":"),
			dimStyle.Render(e.Error),
		)
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).Render(line))
		sb.WriteString("\n")
	}
	return sb.String()
}

func renderASN(a *lookup.ASNResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("ASN"))
	sb.WriteString("\n")

	rows := [][]string{}
	if a.Number != "" {
		rows = append(rows, []string{"AS Number", a.Number})
	}
	if a.Name != "" {
		rows = append(rows, []string{"AS Name", a.Name})
	}
	if a.CIDR != "" {
		rows = append(rows, []string{"Prefix", a.CIDR})
	}
	if a.Country != "" {
		rows = append(rows, []string{"Country", a.Country})
	}
	if a.RIR != "" {
		rows = append(rows, []string{"RIR", a.RIR})
	}

	if len(rows) == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No ASN data")))
		sb.WriteString("\n")
	} else {
		sb.WriteString(renderKVTable(rows))
	}
	return sb.String()
}

func renderCDN(c *lookup.CDNResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("CDN / WAF Detection"))
	sb.WriteString("\n")

	typeLabel := strings.ToUpper(c.Type) // "CDN", "WAF", or "CLOUD"
	var badge string
	switch strings.ToLower(c.Type) {
	case "waf":
		badge = dangerBadge.Render(typeLabel)
	case "cdn":
		badge = warnBadge.Render(typeLabel)
	default:
		badge = successBadge.Render(typeLabel)
	}

	rows := [][]string{
		{"Provider", c.Name},
		{"Type", badge},
	}
	if c.Category != "" {
		rows = append(rows, []string{"Category", c.Category})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderDNSIntel(d *lookup.DNSIntelResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("DNS Intelligence"))
	sb.WriteString("\n")

	// SOA / Reverse Zone
	rows := [][]string{}
	if d.ReverseZone != "" {
		rows = append(rows, []string{"Reverse Zone", d.ReverseZone})
	}
	if d.SOAPrimary != "" {
		rows = append(rows, []string{"SOA Primary", d.SOAPrimary})
	}
	if d.SOAEmail != "" {
		rows = append(rows, []string{"SOA Email", d.SOAEmail})
	}
	if len(d.Nameservers) > 0 {
		rows = append(rows, []string{"Nameservers", strings.Join(d.Nameservers, ", ")})
	}

	if len(rows) > 0 {
		sb.WriteString(renderKVTable(rows))
	}

	// FCrDNS
	if len(d.FCrDNS) > 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Bold(true).Foreground(colorLabel).Render("Forward-Confirmed rDNS"))
		sb.WriteString("\n")
		for _, entry := range d.FCrDNS {
			var status string
			if entry.Confirmed {
				status = successBadge.Render("CONFIRMED")
			} else {
				status = warnBadge.Render("MISMATCH")
			}
			fwdIP := entry.ForwardIP
			if fwdIP == "" {
				fwdIP = "NXDOMAIN"
			}
			sb.WriteString(fieldRow(entry.PTR, fmt.Sprintf("%s -> %s  %s", entry.PTR, fwdIP, status)))
		}
	}

	// Auth vs Recursive PTR comparison
	if d.PTRMismatch {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Render(
			dangerBadge.Render("! PTR MISMATCH: authoritative and recursive resolvers disagree"),
		))
		sb.WriteString("\n")
		if len(d.AuthPTR) > 0 {
			sb.WriteString(fieldRow("Auth PTR", strings.Join(d.AuthPTR, ", ")))
		}
		if len(d.RecursivePTR) > 0 {
			sb.WriteString(fieldRow("Recursive PTR", strings.Join(d.RecursivePTR, ", ")))
		}
	}

	// AXFR
	if d.AXFRSuccess {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Bold(true).Foreground(colorLabel).Render("Zone Transfer (AXFR)"))
		sb.WriteString("\n")
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
			dangerBadge.Render(fmt.Sprintf("AXFR ALLOWED — %d records retrieved", len(d.AXFRRecords))),
		))
		sb.WriteString("\n")
		// Show first 10 records as a preview
		limit := len(d.AXFRRecords)
		if limit > 10 {
			limit = 10
		}
		for _, rec := range d.AXFRRecords[:limit] {
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(5).Render(dimStyle.Render(rec)))
			sb.WriteString("\n")
		}
		if len(d.AXFRRecords) > 10 {
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(5).Render(
				dimStyle.Render(fmt.Sprintf("... and %d more records", len(d.AXFRRecords)-10)),
			))
			sb.WriteString("\n")
		}
	}

	// DNS Trace
	if len(d.Trace) > 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Bold(true).Foreground(colorLabel).Render("DNS Trace (delegation chain)"))
		sb.WriteString("\n")
		for i, hop := range d.Trace {
			prefix := "  "
			if i == len(d.Trace)-1 {
				prefix = "  "
			}
			serverStr := dimStyle.Render(hop.Server)
			queryStr := valueStyle.Render(fmt.Sprintf("%s %s", hop.Query, hop.Type))
			answersStr := ""
			if len(hop.Answers) > 0 {
				answersStr = " -> " + strings.Join(hop.Answers, ", ")
			}
			rcode := ""
			if hop.Rcode != "" && hop.Rcode != "NOERROR" {
				rcode = " " + warnBadge.Render(hop.Rcode)
			}
			line := fmt.Sprintf("%s@%s  %s%s%s", prefix, serverStr, queryStr, answersStr, rcode)
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(line))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func renderForwardDNS(f *lookup.ForwardDNSResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Forward DNS Recon"))
	sb.WriteString("\n")

	if f.Hostname != "" {
		sb.WriteString(fieldRow("Hostname", f.Hostname))
	}

	type recordSet struct {
		label   string
		records []string
	}
	sets := []recordSet{
		{"A", f.A},
		{"AAAA", f.AAAA},
		{"CNAME", f.CNAME},
		{"MX", f.MX},
		{"NS", f.NS},
		{"TXT", f.TXT},
		{"SOA", f.SOA},
		{"CAA", f.CAA},
		{"SRV", f.SRV},
	}

	found := false
	for _, s := range sets {
		if len(s.records) > 0 {
			found = true
			sb.WriteString(fieldRow(s.label, strings.Join(s.records, ", ")))
		}
	}

	if !found {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No forward DNS records found")))
		sb.WriteString("\n")
	}

	return sb.String()
}

func renderPortScan(p *lookup.PortScanResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Port Scan"))
	sb.WriteString("\n")

	if len(p.OpenPorts) == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No open ports detected")))
		sb.WriteString("\n")
		if p.ScanTime != "" {
			sb.WriteString(fieldRow("Scan Time", p.ScanTime))
		}
		return sb.String()
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(borderStyle).
		Headers("Port", "Protocol", "Service", "Banner").
		StyleFunc(func(row, col int) lipgloss.Style {
			s := lipgloss.NewStyle().Padding(0, 1)
			if row == table.HeaderRow {
				return s.Foreground(colorSecondary).Bold(true)
			}
			if row%2 == 0 {
				return s.Foreground(colorValue)
			}
			return s.Foreground(colorLabel)
		}).
		Width(80)

	for _, port := range p.OpenPorts {
		banner := port.Banner
		if len(banner) > 40 {
			banner = banner[:40] + "..."
		}
		t.Row(
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			port.Service,
			banner,
		)
	}

	sb.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(t.Render()))
	sb.WriteString("\n")

	if p.ScanTime != "" {
		sb.WriteString(fieldRow("Scan Time", p.ScanTime))
	}

	return sb.String()
}

func renderWebIntel(wi *lookup.WebIntelResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Web / TLS Intelligence"))
	sb.WriteString("\n")

	// TLS section
	if wi.TLS != nil {
		t := wi.TLS
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).Bold(true).Foreground(colorLabel).Render("TLS Certificate"))
		sb.WriteString("\n")

		rows := [][]string{}
		if t.CommonName != "" {
			rows = append(rows, []string{"Common Name", t.CommonName})
		}
		if t.Issuer != "" {
			rows = append(rows, []string{"Issuer", t.Issuer})
		}
		if len(t.SANs) > 0 {
			sans := strings.Join(t.SANs, ", ")
			if len(sans) > 80 {
				sans = sans[:80] + "..."
			}
			rows = append(rows, []string{"SANs", sans})
		}
		if t.Version != "" {
			rows = append(rows, []string{"TLS Version", t.Version})
		}
		if t.NotBefore != "" {
			rows = append(rows, []string{"Valid From", t.NotBefore})
		}
		if t.NotAfter != "" {
			expiry := t.NotAfter
			if t.Expired {
				expiry = dangerBadge.Render(expiry + " [EXPIRED]")
			}
			rows = append(rows, []string{"Valid Until", expiry})
		}
		sb.WriteString(renderKVTable(rows))
	}

	// HTTP section
	if wi.HTTP != nil {
		h := wi.HTTP
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Bold(true).Foreground(colorLabel).Render("HTTP Metadata"))
		sb.WriteString("\n")

		rows := [][]string{}
		if h.StatusCode != 0 {
			status := fmt.Sprintf("%d", h.StatusCode)
			switch {
			case h.StatusCode >= 500:
				status = dangerBadge.Render(status)
			case h.StatusCode >= 400:
				status = warnBadge.Render(status)
			case h.StatusCode >= 300:
				status = dimStyle.Render(status)
			default:
				status = successBadge.Render(status)
			}
			rows = append(rows, []string{"Status", status})
		}
		if h.Server != "" {
			rows = append(rows, []string{"Server", h.Server})
		}
		if h.PoweredBy != "" {
			rows = append(rows, []string{"X-Powered-By", h.PoweredBy})
		}
		if h.Title != "" {
			rows = append(rows, []string{"Title", h.Title})
		}
		if h.RedirectURL != "" {
			rows = append(rows, []string{"Redirect", h.RedirectURL})
		}
		// Interesting headers
		for k, v := range h.Headers {
			rows = append(rows, []string{k, v})
		}
		sb.WriteString(renderKVTable(rows))
	}

	return sb.String()
}

func renderVirusTotal(vt *lookup.VirusTotalResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("VirusTotal"))
	sb.WriteString("\n")

	if vt.Message != "" && vt.TotalEngines == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render(vt.Message)))
		sb.WriteString("\n")
		return sb.String()
	}

	// Detection ratio badge
	detections := vt.Malicious + vt.Suspicious
	var detBadge string
	switch {
	case detections == 0:
		detBadge = successBadge.Render(fmt.Sprintf("%d/%d", detections, vt.TotalEngines))
	case detections <= 3:
		detBadge = warnBadge.Render(fmt.Sprintf("%d/%d", detections, vt.TotalEngines))
	default:
		detBadge = dangerBadge.Render(fmt.Sprintf("%d/%d", detections, vt.TotalEngines))
	}

	// Reputation badge
	var repBadge string
	switch {
	case vt.Reputation < -10:
		repBadge = dangerBadge.Render(fmt.Sprintf("%d", vt.Reputation))
	case vt.Reputation < 0:
		repBadge = warnBadge.Render(fmt.Sprintf("%d", vt.Reputation))
	default:
		repBadge = successBadge.Render(fmt.Sprintf("%d", vt.Reputation))
	}

	rows := [][]string{
		{"Detections", detBadge + " engines"},
		{"Reputation", repBadge},
	}
	if vt.Malicious > 0 {
		rows = append(rows, []string{"Malicious", dangerBadge.Render(fmt.Sprintf("%d", vt.Malicious))})
	}
	if vt.Suspicious > 0 {
		rows = append(rows, []string{"Suspicious", warnBadge.Render(fmt.Sprintf("%d", vt.Suspicious))})
	}
	rows = append(rows, []string{"Harmless", fmt.Sprintf("%d", vt.Harmless)})
	rows = append(rows, []string{"Undetected", fmt.Sprintf("%d", vt.Undetected)})

	if vt.VotesMalicious > 0 || vt.VotesHarmless > 0 {
		rows = append(rows, []string{"Community Votes", fmt.Sprintf("%d malicious / %d harmless", vt.VotesMalicious, vt.VotesHarmless)})
	}
	if len(vt.FlaggedBy) > 0 {
		rows = append(rows, []string{"Flagged By", strings.Join(vt.FlaggedBy, ", ")})
	}
	if vt.JARM != "" && vt.JARM != "00000000000000000000000000000000000000000000000000000000000000000" {
		jarm := vt.JARM
		if len(jarm) > 32 {
			jarm = jarm[:32] + "..."
		}
		rows = append(rows, []string{"JARM", jarm})
	}
	if vt.Link != "" {
		rows = append(rows, []string{"Link", vt.Link})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderAzureTenant(az *lookup.AzureTenantResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Azure Tenant Lookup"))
	sb.WriteString("\n")

	if !az.Found {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
			dimStyle.Render("Not found in any accessible Azure subscription"),
		))
		sb.WriteString("\n")
		return sb.String()
	}

	badge := cloudBadge.Background(lipgloss.Color("#0078D4")).Render("FOUND IN AZURE")
	sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(badge))
	sb.WriteString("\n\n")

	rows := [][]string{}
	if az.SubscriptionID != "" {
		rows = append(rows, []string{"Subscription", az.SubscriptionID})
	}
	if az.ResourceGroup != "" {
		rows = append(rows, []string{"Resource Group", az.ResourceGroup})
	}
	if az.PublicIPName != "" {
		rows = append(rows, []string{"Public IP Name", az.PublicIPName})
	}
	if az.PrivateIP != "" {
		rows = append(rows, []string{"Private IP", az.PrivateIP})
	}
	if az.PublicIP != "" {
		rows = append(rows, []string{"Public IP", az.PublicIP})
	}
	if az.NICName != "" {
		rows = append(rows, []string{"NIC", az.NICName})
	}
	if az.Location != "" {
		rows = append(rows, []string{"Location", az.Location})
	}
	if az.AllocationMethod != "" {
		rows = append(rows, []string{"Allocation", az.AllocationMethod})
	}
	if az.SKU != "" {
		rows = append(rows, []string{"SKU", az.SKU})
	}
	if az.FQDN != "" {
		rows = append(rows, []string{"FQDN", az.FQDN})
	}
	if az.VPCID != "" {
		rows = append(rows, []string{"VNet", az.VPCID})
	}
	if az.SubnetName != "" {
		rows = append(rows, []string{"Subnet", az.SubnetName})
	}
	if az.AttachedTo != "" {
		rows = append(rows, []string{"Attached To", az.AttachedTo})
	}
	if az.VMName != "" {
		rows = append(rows, []string{"VM Name", az.VMName})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderAWSTenant(aw *lookup.AWSTenantResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("AWS Tenant Lookup"))
	sb.WriteString("\n")

	if !aw.Found {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
			dimStyle.Render("Not found in any accessible AWS account/region"),
		))
		sb.WriteString("\n")
		return sb.String()
	}

	badge := cloudBadge.Background(lipgloss.Color("#FF9900")).Render("FOUND IN AWS")
	sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(badge))
	sb.WriteString("\n\n")

	rows := [][]string{}
	if aw.AccountName != "" {
		rows = append(rows, []string{"Account", fmt.Sprintf("%s (%s)", aw.AccountName, aw.AccountID)})
	} else if aw.AccountID != "" {
		rows = append(rows, []string{"Account", aw.AccountID})
	}
	if aw.Region != "" {
		rows = append(rows, []string{"Region", aw.Region})
	}
	if aw.ResourceType != "" {
		rows = append(rows, []string{"Resource Type", aw.ResourceType})
	}
	if aw.ResourceName != "" {
		rows = append(rows, []string{"Resource Name", aw.ResourceName})
	}
	if aw.IPType != "" {
		rows = append(rows, []string{"IP Type", aw.IPType})
	}
	if aw.PublicIP != "" {
		rows = append(rows, []string{"Public IP", aw.PublicIP})
	}
	if aw.PrivateIP != "" && aw.IPType != "Private" {
		// Only show private IP for public IP lookups (where it's supplemental info)
		rows = append(rows, []string{"Private IP", aw.PrivateIP})
	}
	if aw.InstanceID != "" {
		rows = append(rows, []string{"Instance ID", aw.InstanceID})
	}
	if aw.NetworkInterfaceID != "" {
		rows = append(rows, []string{"ENI", aw.NetworkInterfaceID})
	}
	if aw.AvailabilityZone != "" {
		rows = append(rows, []string{"AZ", aw.AvailabilityZone})
	}
	if aw.VPCID != "" {
		rows = append(rows, []string{"VPC", aw.VPCID})
	}
	if aw.SubnetID != "" {
		rows = append(rows, []string{"Subnet", aw.SubnetID})
	}
	if aw.Description != "" {
		desc := aw.Description
		if len(desc) > 60 {
			desc = desc[:60] + "..."
		}
		rows = append(rows, []string{"Description", desc})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

// --- Helpers ---

func fieldRow(label, value string) string {
	return lipgloss.NewStyle().PaddingLeft(1).Render(
		lipgloss.JoinHorizontal(lipgloss.Top,
			labelStyle.Render(label),
			valueStyle.Render(value),
		),
	) + "\n"
}

func renderKVTable(rows [][]string) string {
	var sb strings.Builder
	for _, row := range rows {
		if len(row) == 2 {
			sb.WriteString(fieldRow(row[0], row[1]))
		}
	}
	return sb.String()
}

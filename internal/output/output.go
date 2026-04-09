package output

import (
	"encoding/csv"
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
	FormatTable     Format = "table"
	FormatJSON      Format = "json"
	FormatMarkdown  Format = "markdown"
	FormatCSV       Format = "csv"
	FormatCSVHeader Format = "csv-header" // CSV with header row (first entry in bulk)
	FormatQuiet     Format = "quiet"      // single-line grepable output
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
	case FormatMarkdown:
		return renderMarkdown(w, result)
	case FormatCSV:
		return renderCSV(w, result, false)
	case FormatCSVHeader:
		return renderCSV(w, result, true)
	case FormatQuiet:
		return renderQuiet(w, result)
	default:
		return renderStyled(w, result)
	}
}

func renderJSON(w io.Writer, result *lookup.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func renderMarkdown(w io.Writer, result *lookup.Result) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# IP Intelligence Report: %s\n\n", result.IP))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	if result.IsPrivate {
		sb.WriteString("> **Note:** Private IP (cloud tenant lookups only)\n\n")
	}

	// Reverse DNS
	if len(result.ReverseDNS) > 0 {
		sb.WriteString("## Reverse DNS\n\n")
		for _, name := range result.ReverseDNS {
			sb.WriteString(fmt.Sprintf("- `%s`\n", name))
		}
		sb.WriteString("\n")
	}

	// ASN
	if result.ASN != nil {
		a := result.ASN
		sb.WriteString("## ASN\n\n")
		sb.WriteString(fmt.Sprintf("| Field | Value |\n|---|---|\n"))
		if a.Number != "" {
			sb.WriteString(fmt.Sprintf("| AS Number | %s |\n", a.Number))
		}
		if a.Name != "" {
			sb.WriteString(fmt.Sprintf("| AS Name | %s |\n", a.Name))
		}
		if a.CIDR != "" {
			sb.WriteString(fmt.Sprintf("| Prefix | %s |\n", a.CIDR))
		}
		if a.Country != "" {
			sb.WriteString(fmt.Sprintf("| Country | %s |\n", a.Country))
		}
		sb.WriteString("\n")
	}

	// RDAP
	if result.RDAP != nil {
		r := result.RDAP
		sb.WriteString("## RDAP / Registration\n\n")
		sb.WriteString("| Field | Value |\n|---|---|\n")
		mdRow := func(label, value string) {
			if value != "" {
				sb.WriteString(fmt.Sprintf("| %s | %s |\n", label, value))
			}
		}
		mdRow("Network", r.Name)
		mdRow("CIDR", r.CIDR)
		mdRow("Organization", r.OrgName)
		mdRow("Country", r.Country)
		mdRow("RIR", r.Source)
		mdRow("Abuse Contact", r.AbuseEmail)
		sb.WriteString("\n")
	}

	// Cloud
	if result.Cloud != nil {
		sb.WriteString("## Cloud Provider\n\n")
		sb.WriteString(fmt.Sprintf("**%s**", result.Cloud.Provider))
		if result.Cloud.Service != "" {
			sb.WriteString(fmt.Sprintf(" — %s", result.Cloud.Service))
		}
		if result.Cloud.Region != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", result.Cloud.Region))
		}
		sb.WriteString("\n\n")
	}

	// Ports
	if result.Ports != nil && len(result.Ports.OpenPorts) > 0 {
		sb.WriteString("## Open Ports (TCP)\n\n")
		sb.WriteString("| Port | Protocol | Service | Banner |\n|---|---|---|---|\n")
		for _, p := range result.Ports.OpenPorts {
			banner := p.Banner
			if len(banner) > 40 {
				banner = banner[:40] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s |\n", p.Port, p.Protocol, p.Service, banner))
		}
		sb.WriteString("\n")
	}

	// Threat Intel summary
	sb.WriteString("## Threat Intelligence\n\n")
	sb.WriteString("| Source | Finding |\n|---|---|\n")

	if result.GreyNoise != nil {
		if result.GreyNoise.Seen {
			sb.WriteString(fmt.Sprintf("| GreyNoise | %s |\n", result.GreyNoise.Classification))
		} else {
			sb.WriteString("| GreyNoise | Not observed |\n")
		}
	}
	if result.AbuseIPDB != nil {
		sb.WriteString(fmt.Sprintf("| AbuseIPDB | Score: %d%%, Reports: %d |\n", result.AbuseIPDB.AbuseScore, result.AbuseIPDB.TotalReports))
	}
	if result.VirusTotal != nil && result.VirusTotal.TotalEngines > 0 {
		sb.WriteString(fmt.Sprintf("| VirusTotal | %d/%d detections, reputation: %d |\n",
			result.VirusTotal.Malicious+result.VirusTotal.Suspicious, result.VirusTotal.TotalEngines, result.VirusTotal.Reputation))
	}
	if result.AlienVault != nil {
		sb.WriteString(fmt.Sprintf("| AlienVault | %d pulses |\n", result.AlienVault.PulseCount))
	}
	if result.ThreatFox != nil {
		sb.WriteString(fmt.Sprintf("| ThreatFox | %d IOCs |\n", result.ThreatFox.IOCCount))
	}
	if result.IPInfo != nil {
		flags := []string{}
		if result.IPInfo.IsVPN {
			flags = append(flags, "VPN")
		}
		if result.IPInfo.IsProxy {
			flags = append(flags, "Proxy")
		}
		if result.IPInfo.IsTor {
			flags = append(flags, "Tor")
		}
		if result.IPInfo.IsRelay {
			flags = append(flags, "Relay")
		}
		if len(flags) > 0 {
			sb.WriteString(fmt.Sprintf("| IPinfo | %s |\n", strings.Join(flags, ", ")))
		}
	}
	sb.WriteString("\n")

	// Tenant lookups
	if result.AzureTenant != nil && result.AzureTenant.Found {
		sb.WriteString("## Azure Tenant\n\n")
		sb.WriteString(fmt.Sprintf("**Found** in subscription `%s`, resource group `%s`\n\n", result.AzureTenant.SubscriptionID, result.AzureTenant.ResourceGroup))
	}
	if result.AWSTenant != nil && result.AWSTenant.Found {
		sb.WriteString("## AWS Tenant\n\n")
		acct := result.AWSTenant.AccountID
		if result.AWSTenant.AccountName != "" {
			acct = result.AWSTenant.AccountName + " (" + acct + ")"
		}
		sb.WriteString(fmt.Sprintf("**Found** in account %s, region `%s`\n\n", acct, result.AWSTenant.Region))
	}
	if result.GCPTenant != nil && result.GCPTenant.Found {
		sb.WriteString("## GCP Tenant\n\n")
		sb.WriteString(fmt.Sprintf("**Found** in project `%s`\n\n", result.GCPTenant.ProjectID))
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("## Provider Errors\n\n")
		for _, e := range result.Errors {
			sb.WriteString(fmt.Sprintf("- **%s:** %s\n", e.Provider, e.Error))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n")
	fmt.Fprint(w, sb.String())
	return nil
}

func renderCSV(w io.Writer, result *lookup.Result, includeHeader bool) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if includeHeader {
		cw.Write([]string{
			"ip", "timestamp", "is_private",
			"reverse_dns", "asn", "as_name", "as_cidr",
			"rdap_org", "rdap_country", "rdap_abuse_email",
			"cloud_provider", "cloud_service", "cloud_region",
			"greynoise_seen", "greynoise_class",
			"abuseipdb_score", "abuseipdb_reports",
			"vt_malicious", "vt_suspicious", "vt_reputation",
			"alienvault_pulses", "threatfox_iocs",
			"ipinfo_vpn", "ipinfo_proxy", "ipinfo_tor",
			"azure_found", "aws_found", "gcp_found",
			"open_ports",
		})
	}

	// Helper for booleans
	boolStr := func(b bool) string {
		if b {
			return "true"
		}
		return "false"
	}

	row := []string{
		result.IP,
		result.Timestamp.Format("2006-01-02T15:04:05Z"),
		boolStr(result.IsPrivate),
	}

	// Reverse DNS
	row = append(row, strings.Join(result.ReverseDNS, ";"))

	// ASN
	if result.ASN != nil {
		row = append(row, result.ASN.Number, result.ASN.Name, result.ASN.CIDR)
	} else {
		row = append(row, "", "", "")
	}

	// RDAP
	if result.RDAP != nil {
		row = append(row, result.RDAP.OrgName, result.RDAP.Country, result.RDAP.AbuseEmail)
	} else {
		row = append(row, "", "", "")
	}

	// Cloud
	if result.Cloud != nil {
		row = append(row, result.Cloud.Provider, result.Cloud.Service, result.Cloud.Region)
	} else {
		row = append(row, "", "", "")
	}

	// GreyNoise
	if result.GreyNoise != nil {
		row = append(row, boolStr(result.GreyNoise.Seen), result.GreyNoise.Classification)
	} else {
		row = append(row, "", "")
	}

	// AbuseIPDB
	if result.AbuseIPDB != nil {
		row = append(row, fmt.Sprintf("%d", result.AbuseIPDB.AbuseScore), fmt.Sprintf("%d", result.AbuseIPDB.TotalReports))
	} else {
		row = append(row, "", "")
	}

	// VirusTotal
	if result.VirusTotal != nil {
		row = append(row, fmt.Sprintf("%d", result.VirusTotal.Malicious), fmt.Sprintf("%d", result.VirusTotal.Suspicious), fmt.Sprintf("%d", result.VirusTotal.Reputation))
	} else {
		row = append(row, "", "", "")
	}

	// AlienVault
	if result.AlienVault != nil {
		row = append(row, fmt.Sprintf("%d", result.AlienVault.PulseCount))
	} else {
		row = append(row, "")
	}

	// ThreatFox
	if result.ThreatFox != nil {
		row = append(row, fmt.Sprintf("%d", result.ThreatFox.IOCCount))
	} else {
		row = append(row, "")
	}

	// IPinfo privacy
	if result.IPInfo != nil {
		row = append(row, boolStr(result.IPInfo.IsVPN), boolStr(result.IPInfo.IsProxy), boolStr(result.IPInfo.IsTor))
	} else {
		row = append(row, "", "", "")
	}

	// Tenant lookups
	if result.AzureTenant != nil {
		row = append(row, boolStr(result.AzureTenant.Found))
	} else {
		row = append(row, "")
	}
	if result.AWSTenant != nil {
		row = append(row, boolStr(result.AWSTenant.Found))
	} else {
		row = append(row, "")
	}
	if result.GCPTenant != nil {
		row = append(row, boolStr(result.GCPTenant.Found))
	} else {
		row = append(row, "")
	}

	// Open ports
	if result.Ports != nil && len(result.Ports.OpenPorts) > 0 {
		ports := make([]string, len(result.Ports.OpenPorts))
		for i, p := range result.Ports.OpenPorts {
			ports[i] = fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		}
		row = append(row, strings.Join(ports, ";"))
	} else {
		row = append(row, "")
	}

	cw.Write(row)
	return nil
}

func renderQuiet(w io.Writer, result *lookup.Result) error {
	// Single-line output: ip [flags] [threat-scores] [cloud]
	var parts []string
	parts = append(parts, result.IP)

	// Cloud provider
	if result.Cloud != nil {
		parts = append(parts, fmt.Sprintf("cloud=%s", result.Cloud.Provider))
	}

	// Threat scores
	if result.AbuseIPDB != nil && result.AbuseIPDB.AbuseScore > 0 {
		parts = append(parts, fmt.Sprintf("abuse=%d%%", result.AbuseIPDB.AbuseScore))
	}
	if result.VirusTotal != nil && result.VirusTotal.Malicious > 0 {
		parts = append(parts, fmt.Sprintf("vt_mal=%d", result.VirusTotal.Malicious))
	}
	if result.GreyNoise != nil && result.GreyNoise.Seen {
		parts = append(parts, fmt.Sprintf("greynoise=%s", result.GreyNoise.Classification))
	}
	if result.AlienVault != nil && result.AlienVault.PulseCount > 0 {
		parts = append(parts, fmt.Sprintf("otx_pulses=%d", result.AlienVault.PulseCount))
	}
	if result.ThreatFox != nil && result.ThreatFox.IOCCount > 0 {
		parts = append(parts, fmt.Sprintf("threatfox=%d", result.ThreatFox.IOCCount))
	}

	// Privacy flags
	if result.IPInfo != nil {
		if result.IPInfo.IsVPN {
			parts = append(parts, "VPN")
		}
		if result.IPInfo.IsProxy {
			parts = append(parts, "PROXY")
		}
		if result.IPInfo.IsTor {
			parts = append(parts, "TOR")
		}
	}

	// Tenant matches
	if result.AzureTenant != nil && result.AzureTenant.Found {
		parts = append(parts, "AZURE")
	}
	if result.AWSTenant != nil && result.AWSTenant.Found {
		parts = append(parts, "AWS")
	}
	if result.GCPTenant != nil && result.GCPTenant.Found {
		parts = append(parts, "GCP")
	}

	// Open ports
	if result.Ports != nil && len(result.Ports.OpenPorts) > 0 {
		ports := make([]string, len(result.Ports.OpenPorts))
		for i, p := range result.Ports.OpenPorts {
			ports[i] = fmt.Sprintf("%d", p.Port)
		}
		parts = append(parts, fmt.Sprintf("ports=%s", strings.Join(ports, ",")))
	}

	fmt.Fprintln(w, strings.Join(parts, " "))
	return nil
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

	// GCP Tenant
	if result.GCPTenant != nil {
		sb.WriteString(renderGCPTenant(result.GCPTenant))
	}

	// --- Active Scanning ---

	// JARM TLS Fingerprint
	if result.JARM != nil {
		sb.WriteString(renderJARM(result.JARM))
	}

	// UDP Scan
	if result.UDPScan != nil {
		sb.WriteString(renderUDPScan(result.UDPScan))
	}

	// --- Additional Threat Intel ---

	// AlienVault OTX
	if result.AlienVault != nil {
		sb.WriteString(renderAlienVault(result.AlienVault))
	}

	// Censys
	if result.Censys != nil {
		sb.WriteString(renderCensys(result.Censys))
	}

	// IPinfo.io
	if result.IPInfo != nil {
		sb.WriteString(renderIPInfo(result.IPInfo))
	}

	// ThreatFox
	if result.ThreatFox != nil {
		sb.WriteString(renderThreatFox(result.ThreatFox))
	}

	// Tech Stack
	if result.TechStack != nil && len(result.TechStack.Technologies) > 0 {
		sb.WriteString(renderTechStack(result.TechStack))
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

func renderGCPTenant(gcp *lookup.GCPTenantResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("GCP Tenant Lookup"))
	sb.WriteString("\n")

	if !gcp.Found {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
			dimStyle.Render("Not found in any accessible GCP project"),
		))
		sb.WriteString("\n")
		return sb.String()
	}

	badge := cloudBadge.Background(lipgloss.Color("#4285F4")).Render("FOUND IN GCP")
	sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(badge))
	sb.WriteString("\n\n")

	rows := [][]string{}
	if gcp.ProjectID != "" {
		rows = append(rows, []string{"Project", gcp.ProjectID})
	}
	if gcp.ResourceType != "" {
		rows = append(rows, []string{"Resource Type", gcp.ResourceType})
	}
	if gcp.IPName != "" {
		rows = append(rows, []string{"IP Name", gcp.IPName})
	}
	if gcp.IPType != "" {
		rows = append(rows, []string{"IP Type", gcp.IPType})
	}
	if gcp.Status != "" {
		rows = append(rows, []string{"Status", gcp.Status})
	}
	if gcp.Scope != "" {
		rows = append(rows, []string{"Scope", gcp.Scope})
	}
	if gcp.Region != "" {
		rows = append(rows, []string{"Region", gcp.Region})
	}
	if gcp.Zone != "" {
		rows = append(rows, []string{"Zone", gcp.Zone})
	}
	if gcp.InstanceName != "" {
		rows = append(rows, []string{"Instance", gcp.InstanceName})
	}
	if gcp.PublicIP != "" {
		rows = append(rows, []string{"Public IP", gcp.PublicIP})
	}
	if gcp.PrivateIP != "" {
		rows = append(rows, []string{"Private IP", gcp.PrivateIP})
	}
	if gcp.Network != "" {
		rows = append(rows, []string{"Network", gcp.Network})
	}
	if gcp.Subnet != "" {
		rows = append(rows, []string{"Subnet", gcp.Subnet})
	}
	if gcp.AttachedTo != "" {
		rows = append(rows, []string{"Attached To", gcp.AttachedTo})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderJARM(j *lookup.JARMResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("JARM TLS Fingerprint"))
	sb.WriteString("\n")

	if j.Fingerprint == "" || j.Fingerprint == strings.Repeat("0", 62) {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No JARM fingerprint (no TLS response)")))
		sb.WriteString("\n")
		return sb.String()
	}

	rows := [][]string{
		{"Fingerprint", j.Fingerprint},
	}
	if j.Port != 0 {
		rows = append(rows, []string{"Port", fmt.Sprintf("%d", j.Port)})
	}

	sb.WriteString(renderKVTable(rows))
	return sb.String()
}

func renderUDPScan(u *lookup.UDPScanResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("UDP Scan"))
	sb.WriteString("\n")

	if len(u.OpenPorts) == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No UDP services responded")))
		sb.WriteString("\n")
		if u.ScanTime != "" {
			sb.WriteString(fieldRow("Scan Time", u.ScanTime))
		}
		return sb.String()
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(borderStyle).
		Headers("Port", "Service", "Response", "Amplification").
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

	for _, port := range u.OpenPorts {
		amp := ""
		if port.Amplification {
			amp = dangerBadge.Render(port.AmpFactor)
		}
		t.Row(
			fmt.Sprintf("%d", port.Port),
			port.Service,
			fmt.Sprintf("%d bytes", port.ResponseSize),
			amp,
		)
	}

	sb.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(t.Render()))
	sb.WriteString("\n")

	if u.ScanTime != "" {
		sb.WriteString(fieldRow("Scan Time", u.ScanTime))
	}

	return sb.String()
}

func renderAlienVault(av *lookup.AlienVaultResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("AlienVault OTX"))
	sb.WriteString("\n")

	if av.PulseCount == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No threat pulses found")))
		sb.WriteString("\n")
		return sb.String()
	}

	var pulseBadge string
	switch {
	case av.PulseCount >= 10:
		pulseBadge = dangerBadge.Render(fmt.Sprintf("%d pulses", av.PulseCount))
	case av.PulseCount >= 3:
		pulseBadge = warnBadge.Render(fmt.Sprintf("%d pulses", av.PulseCount))
	default:
		pulseBadge = successBadge.Render(fmt.Sprintf("%d pulses", av.PulseCount))
	}

	rows := [][]string{
		{"Pulses", pulseBadge},
	}
	if av.Reputation != 0 {
		rows = append(rows, []string{"Reputation", fmt.Sprintf("%d", av.Reputation)})
	}
	if av.Country != "" {
		rows = append(rows, []string{"Country", av.Country})
	}
	if av.ASN != "" {
		rows = append(rows, []string{"ASN", av.ASN})
	}
	if len(av.Tags) > 0 {
		tags := strings.Join(av.Tags, ", ")
		if len(tags) > 60 {
			tags = tags[:60] + "..."
		}
		rows = append(rows, []string{"Tags", tags})
	}
	if av.Link != "" {
		rows = append(rows, []string{"Link", av.Link})
	}

	sb.WriteString(renderKVTable(rows))

	// Show top pulses
	if len(av.Pulses) > 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Bold(true).Foreground(colorLabel).Render("Recent Pulses"))
		sb.WriteString("\n")
		limit := len(av.Pulses)
		if limit > 5 {
			limit = 5
		}
		for _, pulse := range av.Pulses[:limit] {
			name := pulse.Name
			if len(name) > 60 {
				name = name[:60] + "..."
			}
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
				fmt.Sprintf("%s  %s", valueStyle.Render(name), dimStyle.Render(pulse.Created)),
			))
			sb.WriteString("\n")
		}
		if len(av.Pulses) > 5 {
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
				dimStyle.Render(fmt.Sprintf("... and %d more", len(av.Pulses)-5)),
			))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func renderCensys(c *lookup.CensysResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Censys"))
	sb.WriteString("\n")

	if c.Services == 0 && len(c.OpenPorts) == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No data found in Censys")))
		sb.WriteString("\n")
		return sb.String()
	}

	rows := [][]string{
		{"Services", fmt.Sprintf("%d", c.Services)},
	}
	if c.OperatingSystem != "" {
		rows = append(rows, []string{"OS", c.OperatingSystem})
	}
	if c.ASN != 0 {
		rows = append(rows, []string{"ASN", fmt.Sprintf("AS%d (%s)", c.ASN, c.ASName)})
	}
	if c.Country != "" {
		rows = append(rows, []string{"Country", c.Country})
	}
	if c.LastUpdated != "" {
		rows = append(rows, []string{"Last Updated", c.LastUpdated})
	}
	if c.Link != "" {
		rows = append(rows, []string{"Link", c.Link})
	}

	sb.WriteString(renderKVTable(rows))

	if len(c.OpenPorts) > 0 {
		t := table.New().
			Border(lipgloss.NormalBorder()).
			BorderStyle(borderStyle).
			Headers("Port", "Protocol", "Service", "Certificate").
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

		for _, svc := range c.OpenPorts {
			cert := svc.Certificate
			if len(cert) > 30 {
				cert = cert[:30] + "..."
			}
			t.Row(
				fmt.Sprintf("%d", svc.Port),
				svc.Protocol,
				svc.ServiceName,
				cert,
			)
		}

		sb.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(t.Render()))
		sb.WriteString("\n")
	}

	return sb.String()
}

func renderIPInfo(info *lookup.IPInfoResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("IPinfo.io"))
	sb.WriteString("\n")

	rows := [][]string{}
	if info.Hostname != "" {
		rows = append(rows, []string{"Hostname", info.Hostname})
	}
	if info.Org != "" {
		rows = append(rows, []string{"Organization", info.Org})
	}
	if info.City != "" || info.Region != "" {
		loc := info.City
		if info.Region != "" {
			if loc != "" {
				loc += ", "
			}
			loc += info.Region
		}
		if info.Country != "" {
			loc += " (" + info.Country + ")"
		}
		rows = append(rows, []string{"Location", loc})
	}
	if info.Timezone != "" {
		rows = append(rows, []string{"Timezone", info.Timezone})
	}

	// Privacy flags
	privacyFlags := []string{}
	if info.IsVPN {
		privacyFlags = append(privacyFlags, dangerBadge.Render("VPN"))
	}
	if info.IsProxy {
		privacyFlags = append(privacyFlags, dangerBadge.Render("PROXY"))
	}
	if info.IsTor {
		privacyFlags = append(privacyFlags, dangerBadge.Render("TOR"))
	}
	if info.IsRelay {
		privacyFlags = append(privacyFlags, warnBadge.Render("RELAY"))
	}
	if info.IsHosting {
		privacyFlags = append(privacyFlags, dimStyle.Render("HOSTING"))
	}
	if len(privacyFlags) > 0 {
		rows = append(rows, []string{"Privacy", strings.Join(privacyFlags, " ")})
	}
	if info.PrivacyService != "" {
		rows = append(rows, []string{"Service", info.PrivacyService})
	}

	if len(rows) == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No data from IPinfo")))
		sb.WriteString("\n")
	} else {
		sb.WriteString(renderKVTable(rows))
	}

	return sb.String()
}

func renderThreatFox(tf *lookup.ThreatFoxResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("ThreatFox (abuse.ch)"))
	sb.WriteString("\n")

	if tf.IOCCount == 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(dimStyle.Render("No IOCs found in ThreatFox")))
		sb.WriteString("\n")
		return sb.String()
	}

	iocBadge := dangerBadge.Render(fmt.Sprintf("%d IOCs", tf.IOCCount))
	rows := [][]string{
		{"IOCs", iocBadge},
	}
	if len(tf.MalwareFamilies) > 0 {
		rows = append(rows, []string{"Malware", dangerBadge.Render(strings.Join(tf.MalwareFamilies, ", "))})
	}
	if len(tf.ThreatTypes) > 0 {
		rows = append(rows, []string{"Threat Types", strings.Join(tf.ThreatTypes, ", ")})
	}
	if tf.Link != "" {
		rows = append(rows, []string{"Link", tf.Link})
	}

	sb.WriteString(renderKVTable(rows))

	// Show top IOCs
	if len(tf.IOCs) > 0 {
		sb.WriteString(lipgloss.NewStyle().PaddingLeft(1).PaddingTop(1).Bold(true).Foreground(colorLabel).Render("IOC Details"))
		sb.WriteString("\n")
		limit := len(tf.IOCs)
		if limit > 5 {
			limit = 5
		}
		for _, ioc := range tf.IOCs[:limit] {
			line := fmt.Sprintf("%s  %s  conf:%d  %s",
				dangerBadge.Render(ioc.Malware),
				dimStyle.Render(ioc.Type),
				ioc.Confidence,
				dimStyle.Render(ioc.FirstSeen),
			)
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(line))
			sb.WriteString("\n")
		}
		if len(tf.IOCs) > 5 {
			sb.WriteString(lipgloss.NewStyle().PaddingLeft(3).Render(
				dimStyle.Render(fmt.Sprintf("... and %d more", len(tf.IOCs)-5)),
			))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func renderTechStack(ts *lookup.TechStackResult) string {
	var sb strings.Builder
	sb.WriteString(sectionHeaderStyle.Render("Tech Stack Detection"))
	sb.WriteString("\n")

	if ts.URL != "" {
		sb.WriteString(fieldRow("URL", ts.URL))
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(borderStyle).
		Headers("Technology", "Categories", "Version").
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

	for _, tech := range ts.Technologies {
		cats := strings.Join(tech.Categories, ", ")
		if len(cats) > 30 {
			cats = cats[:30] + "..."
		}
		t.Row(tech.Name, cats, tech.Version)
	}

	sb.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(t.Render()))
	sb.WriteString("\n")

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

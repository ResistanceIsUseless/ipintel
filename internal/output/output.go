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
	header := lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render("IP Intelligence Report"),
		lipgloss.NewStyle().Bold(true).Foreground(colorValue).PaddingLeft(1).Render(result.IP),
		subtitleStyle.Render(result.Timestamp.Format("2006-01-02 15:04:05 UTC")),
	)
	sb.WriteString(boxStyle.Render(header))
	sb.WriteString("\n")

	// Reverse DNS
	sb.WriteString(renderReverseDNS(result))

	// RDAP
	if result.RDAP != nil {
		sb.WriteString(renderRDAP(result.RDAP))
	}

	// Cloud Provider
	if result.Cloud != nil {
		sb.WriteString(renderCloud(result.Cloud))
	}

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

	// Certificates
	if len(result.Certificates) > 0 {
		sb.WriteString(renderCerts(result.Certificates))
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

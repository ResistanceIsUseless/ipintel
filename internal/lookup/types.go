package lookup

import (
	"context"
	"net"
	"time"
)

// Result aggregates all intelligence gathered about an IP.
type Result struct {
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`

	// Reverse DNS
	ReverseDNS []string `json:"reverse_dns,omitempty"`

	// RDAP / ARIN Whois
	RDAP *RDAPResult `json:"rdap,omitempty"`

	// Cloud provider detection
	Cloud *CloudResult `json:"cloud,omitempty"`

	// GreyNoise
	GreyNoise *GreyNoiseResult `json:"greynoise,omitempty"`

	// AbuseIPDB
	AbuseIPDB *AbuseIPDBResult `json:"abuseipdb,omitempty"`

	// Shodan
	Shodan *ShodanResult `json:"shodan,omitempty"`

	// Certificate Transparency (crt.sh)
	Certificates []CertResult `json:"certificates,omitempty"`

	// Errors from individual providers (non-fatal)
	Errors []ProviderError `json:"errors,omitempty"`
}

type RDAPResult struct {
	Name       string `json:"name,omitempty"`
	Handle     string `json:"handle,omitempty"`
	StartAddr  string `json:"start_address,omitempty"`
	EndAddr    string `json:"end_address,omitempty"`
	CIDR       string `json:"cidr,omitempty"`
	OrgName    string `json:"org_name,omitempty"`
	Country    string `json:"country,omitempty"`
	Type       string `json:"type,omitempty"`
	AbuseEmail string `json:"abuse_email,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

type CloudResult struct {
	Provider    string `json:"provider"`
	Service     string `json:"service,omitempty"`
	Region      string `json:"region,omitempty"`
	NetworkCIDR string `json:"network_cidr,omitempty"`
}

type GreyNoiseResult struct {
	Seen           bool   `json:"seen"`
	Classification string `json:"classification,omitempty"`
	Name           string `json:"name,omitempty"`
	Noise          bool   `json:"noise"`
	RIOT           bool   `json:"riot"`
	Link           string `json:"link,omitempty"`
	LastSeen       string `json:"last_seen,omitempty"`
	Message        string `json:"message,omitempty"`
}

type AbuseIPDBResult struct {
	AbuseScore     int    `json:"abuse_score"`
	TotalReports   int    `json:"total_reports"`
	CountryCode    string `json:"country_code,omitempty"`
	ISP            string `json:"isp,omitempty"`
	Domain         string `json:"domain,omitempty"`
	UsageType      string `json:"usage_type,omitempty"`
	IsWhitelisted  bool   `json:"is_whitelisted"`
	LastReportedAt string `json:"last_reported_at,omitempty"`
}

type ShodanResult struct {
	OS         string   `json:"os,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	Hostnames  []string `json:"hostnames,omitempty"`
	ISP        string   `json:"isp,omitempty"`
	Org        string   `json:"org,omitempty"`
	Vulns      []string `json:"vulns,omitempty"`
	LastUpdate string   `json:"last_update,omitempty"`
}

type CertResult struct {
	CommonName string `json:"common_name"`
	Issuer     string `json:"issuer,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	SANs       string `json:"sans,omitempty"`
}

type ProviderError struct {
	Provider string `json:"provider"`
	Error    string `json:"error"`
}

// Provider is the interface all intelligence sources implement.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, ip net.IP) error
	Apply(result *Result)
}

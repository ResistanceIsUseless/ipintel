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

	// DNS Intelligence (SOA/NS, FCrDNS, auth NS comparison, AXFR, trace)
	DNSIntel *DNSIntelResult `json:"dns_intel,omitempty"`

	// Forward DNS recon (record queries on PTR hostnames)
	ForwardDNS *ForwardDNSResult `json:"forward_dns,omitempty"`

	// RDAP / ARIN Whois
	RDAP *RDAPResult `json:"rdap,omitempty"`

	// ASN information
	ASN *ASNResult `json:"asn,omitempty"`

	// Cloud provider detection
	Cloud *CloudResult `json:"cloud,omitempty"`

	// CDN / WAF detection
	CDN *CDNResult `json:"cdn,omitempty"`

	// Port scan results
	Ports *PortScanResult `json:"ports,omitempty"`

	// TLS/HTTP metadata
	WebIntel *WebIntelResult `json:"web_intel,omitempty"`

	// GreyNoise
	GreyNoise *GreyNoiseResult `json:"greynoise,omitempty"`

	// AbuseIPDB
	AbuseIPDB *AbuseIPDBResult `json:"abuseipdb,omitempty"`

	// Shodan
	Shodan *ShodanResult `json:"shodan,omitempty"`

	// VirusTotal
	VirusTotal *VirusTotalResult `json:"virustotal,omitempty"`

	// Certificate Transparency (crt.sh)
	Certificates []CertResult `json:"certificates,omitempty"`

	// Azure tenant lookup (authenticated)
	AzureTenant *AzureTenantResult `json:"azure_tenant,omitempty"`

	// AWS tenant lookup (authenticated)
	AWSTenant *AWSTenantResult `json:"aws_tenant,omitempty"`

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

// CDNResult holds CDN/WAF detection from cdncheck.
type CDNResult struct {
	Detected bool   `json:"detected"`
	Name     string `json:"name,omitempty"`     // provider name (e.g., "cloudflare", "akamai")
	Type     string `json:"type,omitempty"`     // "cdn", "waf", or "cloud"
	Category string `json:"category,omitempty"` // human-readable label
}

// ASNResult holds BGP/ASN information about an IP.
type ASNResult struct {
	Number  string   `json:"as_number,omitempty"`  // e.g., "AS13335"
	Name    string   `json:"as_name,omitempty"`    // e.g., "CLOUDFLARENET"
	Country string   `json:"as_country,omitempty"` // e.g., "US"
	CIDR    string   `json:"as_cidr,omitempty"`    // e.g., "104.16.0.0/13"
	Ranges  []string `json:"as_ranges,omitempty"`  // all announced prefixes
	RIR     string   `json:"rir,omitempty"`        // Regional Internet Registry
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

// --- DNS Intelligence results ---

type DNSIntelResult struct {
	// Reverse zone SOA/NS info
	ReverseZone string   `json:"reverse_zone,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	SOAPrimary  string   `json:"soa_primary,omitempty"`
	SOAEmail    string   `json:"soa_email,omitempty"`

	// Forward-Confirmed reverse DNS
	FCrDNS []FCrDNSEntry `json:"fcrdns,omitempty"`

	// Authoritative NS comparison
	AuthPTR      []string `json:"auth_ptr,omitempty"`      // PTR from authoritative NS
	RecursivePTR []string `json:"recursive_ptr,omitempty"` // PTR from recursive resolver
	PTRMismatch  bool     `json:"ptr_mismatch"`            // true if auth != recursive

	// AXFR results (zone transfer attempt)
	AXFRSuccess bool     `json:"axfr_success"`
	AXFRRecords []string `json:"axfr_records,omitempty"` // records from zone transfer

	// DNS trace (delegation chain from root)
	Trace []TraceHop `json:"trace,omitempty"`
}

type FCrDNSEntry struct {
	PTR       string `json:"ptr"`
	ForwardIP string `json:"forward_ip,omitempty"` // what the PTR hostname resolves to
	Confirmed bool   `json:"confirmed"`            // forward IP matches original IP
}

// TraceHop represents one step in a DNS delegation trace.
type TraceHop struct {
	Server  string   `json:"server"`            // nameserver queried
	Query   string   `json:"query"`             // what was queried
	Type    string   `json:"type"`              // query type (e.g., "PTR", "NS")
	Answers []string `json:"answers,omitempty"` // answers received
	Rcode   string   `json:"rcode,omitempty"`   // response code
}

// --- Forward DNS recon results ---

// ForwardDNSResult contains DNS record queries run against PTR hostnames.
type ForwardDNSResult struct {
	Hostname string   `json:"hostname"`        // the PTR hostname we queried
	A        []string `json:"a,omitempty"`     // A records
	AAAA     []string `json:"aaaa,omitempty"`  // AAAA records
	CNAME    []string `json:"cname,omitempty"` // CNAME records
	MX       []string `json:"mx,omitempty"`    // MX records
	NS       []string `json:"ns,omitempty"`    // NS records
	TXT      []string `json:"txt,omitempty"`   // TXT records
	SOA      []string `json:"soa,omitempty"`   // SOA records
	CAA      []string `json:"caa,omitempty"`   // CAA records
	SRV      []string `json:"srv,omitempty"`   // SRV records
}

// --- Port scan results ---

type PortScanResult struct {
	OpenPorts []PortInfo `json:"open_ports,omitempty"`
	ScanTime  string     `json:"scan_time,omitempty"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

// --- Web/TLS intelligence ---

type WebIntelResult struct {
	TLS  *TLSInfo  `json:"tls,omitempty"`
	HTTP *HTTPInfo `json:"http,omitempty"`
}

type TLSInfo struct {
	CommonName string   `json:"common_name,omitempty"`
	SANs       []string `json:"sans,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	Version    string   `json:"version,omitempty"` // TLS 1.2, 1.3, etc.
	Expired    bool     `json:"expired"`
}

type HTTPInfo struct {
	StatusCode  int               `json:"status_code,omitempty"`
	Server      string            `json:"server,omitempty"`
	PoweredBy   string            `json:"powered_by,omitempty"`
	Title       string            `json:"title,omitempty"`
	RedirectURL string            `json:"redirect_url,omitempty"`
	Headers     map[string]string `json:"interesting_headers,omitempty"` // security headers, etc.
}

// --- VirusTotal results ---

type VirusTotalResult struct {
	Reputation     int      `json:"reputation"`                // community score (negative = bad)
	Malicious      int      `json:"malicious"`                 // engines flagging as malicious
	Suspicious     int      `json:"suspicious"`                // engines flagging as suspicious
	Harmless       int      `json:"harmless"`                  // engines flagging as harmless
	Undetected     int      `json:"undetected"`                // engines with no verdict
	TotalEngines   int      `json:"total_engines"`             // total engines that analyzed
	ASN            int      `json:"asn,omitempty"`             // AS number
	ASOwner        string   `json:"as_owner,omitempty"`        // AS owner name
	Country        string   `json:"country,omitempty"`         // country code
	Network        string   `json:"network,omitempty"`         // CIDR
	JARM           string   `json:"jarm,omitempty"`            // JARM fingerprint
	VotesMalicious int      `json:"votes_malicious,omitempty"` // community malicious votes
	VotesHarmless  int      `json:"votes_harmless,omitempty"`  // community harmless votes
	FlaggedBy      []string `json:"flagged_by,omitempty"`      // top engines that flagged it
	Link           string   `json:"link,omitempty"`            // VT GUI link
	Message        string   `json:"message,omitempty"`         // status message (e.g., not found)
}

// --- Azure tenant results ---

type AzureTenantResult struct {
	Found              bool   `json:"found"`
	SubscriptionID     string `json:"subscription_id,omitempty"`
	ResourceGroup      string `json:"resource_group,omitempty"`
	ResourceID         string `json:"resource_id,omitempty"`
	PublicIPName       string `json:"public_ip_name,omitempty"`
	Location           string `json:"location,omitempty"`
	AllocationMethod   string `json:"allocation_method,omitempty"` // Static or Dynamic
	SKU                string `json:"sku,omitempty"`               // Basic or Standard
	FQDN               string `json:"fqdn,omitempty"`
	AttachedTo         string `json:"attached_to,omitempty"`          // resource type (VM, LB, etc.)
	AttachedResourceID string `json:"attached_resource_id,omitempty"` // full ARM ID
	VMName             string `json:"vm_name,omitempty"`              // if attached to a VM
}

// --- AWS tenant results ---

type AWSTenantResult struct {
	Found              bool   `json:"found"`
	Region             string `json:"region,omitempty"`
	IPType             string `json:"ip_type,omitempty"` // "Elastic IP" or "Ephemeral"
	PublicIP           string `json:"public_ip,omitempty"`
	PrivateIP          string `json:"private_ip,omitempty"`
	InstanceID         string `json:"instance_id,omitempty"`
	NetworkInterfaceID string `json:"network_interface_id,omitempty"`
	AllocationID       string `json:"allocation_id,omitempty"`
	AssociationID      string `json:"association_id,omitempty"`
	ResourceType       string `json:"resource_type,omitempty"` // EC2, NAT Gateway, NLB, etc.
	Description        string `json:"description,omitempty"`
	AccountID          string `json:"account_id,omitempty"`
	AvailabilityZone   string `json:"availability_zone,omitempty"`
	VPCID              string `json:"vpc_id,omitempty"`
	SubnetID           string `json:"subnet_id,omitempty"`
}

// Provider is the interface all intelligence sources implement.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, ip net.IP) error
	Apply(result *Result)
}

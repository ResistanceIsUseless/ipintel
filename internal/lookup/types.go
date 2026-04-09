package lookup

import (
	"context"
	"net"
	"time"
)

// Result aggregates all intelligence gathered about an IP.
type Result struct {
	IP        string    `json:"ip"`
	IsPrivate bool      `json:"is_private,omitempty"` // true for RFC 1918/link-local/loopback IPs
	Timestamp time.Time `json:"timestamp"`

	// Reverse DNS
	ReverseDNS []string `json:"reverse_dns,omitempty"`

	// DNS Intelligence (SOA/NS, FCrDNS, auth NS comparison, AXFR, trace)
	DNSIntel *DNSIntelResult `json:"dns_intel,omitempty"`

	// Forward DNS recon (record queries on PTR hostnames)
	ForwardDNS *ForwardDNSResult `json:"forward_dns,omitempty"`

	// RDAP registration (all 5 RIRs via IANA bootstrap)
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

	// GCP tenant lookup (authenticated)
	GCPTenant *GCPTenantResult `json:"gcp_tenant,omitempty"`

	// JARM TLS fingerprinting (active)
	JARM *JARMResult `json:"jarm,omitempty"`

	// UDP port scan
	UDPScan *UDPScanResult `json:"udp_scan,omitempty"`

	// AlienVault OTX
	AlienVault *AlienVaultResult `json:"alienvault,omitempty"`

	// Censys host intelligence
	Censys *CensysResult `json:"censys,omitempty"`

	// IPinfo.io (VPN/proxy/Tor/relay detection)
	IPInfo *IPInfoResult `json:"ipinfo,omitempty"`

	// ThreatFox (abuse.ch) IOC search
	ThreatFox *ThreatFoxResult `json:"threatfox,omitempty"`

	// Tech stack detection (Wappalyzer)
	TechStack *TechStackResult `json:"tech_stack,omitempty"`

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
	Source     string `json:"source,omitempty"` // RIR that served the response (e.g., "ARIN", "RIPE")
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
	PrivateIP          string `json:"private_ip,omitempty"` // private IP of the NIC
	PublicIP           string `json:"public_ip,omitempty"`  // associated public IP (when searching by private)
	Location           string `json:"location,omitempty"`
	AllocationMethod   string `json:"allocation_method,omitempty"` // Static or Dynamic
	SKU                string `json:"sku,omitempty"`               // Basic or Standard
	FQDN               string `json:"fqdn,omitempty"`
	AttachedTo         string `json:"attached_to,omitempty"`          // resource type (VM, LB, etc.)
	AttachedResourceID string `json:"attached_resource_id,omitempty"` // full ARM ID
	VMName             string `json:"vm_name,omitempty"`              // if attached to a VM
	NICName            string `json:"nic_name,omitempty"`             // network interface name
	VPCID              string `json:"vnet,omitempty"`                 // virtual network name
	SubnetName         string `json:"subnet,omitempty"`               // subnet name
}

// --- AWS tenant results ---

type AWSTenantResult struct {
	Found              bool   `json:"found"`
	Region             string `json:"region,omitempty"`
	AccountID          string `json:"account_id,omitempty"`
	AccountName        string `json:"account_name,omitempty"` // SSO account display name
	IPType             string `json:"ip_type,omitempty"`      // "Elastic IP" or "Ephemeral"
	PublicIP           string `json:"public_ip,omitempty"`
	PrivateIP          string `json:"private_ip,omitempty"`
	InstanceID         string `json:"instance_id,omitempty"`
	NetworkInterfaceID string `json:"network_interface_id,omitempty"`
	AllocationID       string `json:"allocation_id,omitempty"`
	AssociationID      string `json:"association_id,omitempty"`
	ResourceType       string `json:"resource_type,omitempty"` // EC2, NAT Gateway, NLB, etc.
	ResourceName       string `json:"resource_name,omitempty"` // Name tag value
	Description        string `json:"description,omitempty"`
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

// PrivateIPProvider is implemented by providers that can look up private/RFC1918 IPs.
// Providers that don't implement this interface are skipped for private IP lookups.
type PrivateIPProvider interface {
	Provider
	SupportsPrivateIP() bool
}

// HostnameAwareProvider is implemented by providers that benefit from knowing
// hostnames discovered by earlier providers (rDNS, crt.sh, forward DNS, etc.).
// The engine runs these providers in a second phase after hostname-producing
// providers have completed, calling SetHostnames with the aggregated list
// before invoking Lookup.
type HostnameAwareProvider interface {
	Provider
	SetHostnames(hostnames []string)
}

// --- GCP tenant results ---

type GCPTenantResult struct {
	Found        bool   `json:"found"`
	ProjectID    string `json:"project_id,omitempty"`
	Region       string `json:"region,omitempty"`
	Zone         string `json:"zone,omitempty"`
	InstanceName string `json:"instance_name,omitempty"`
	PublicIP     string `json:"public_ip,omitempty"`
	PrivateIP    string `json:"private_ip,omitempty"`
	IPName       string `json:"ip_name,omitempty"`
	IPType       string `json:"ip_type,omitempty"` // "EXTERNAL", "INTERNAL", etc.
	Status       string `json:"status,omitempty"`
	Scope        string `json:"scope,omitempty"` // "global" or "regional"
	Subnet       string `json:"subnet,omitempty"`
	Network      string `json:"network,omitempty"`
	ResourceType string `json:"resource_type,omitempty"` // "Address", "Instance", "ForwardingRule"
	AttachedTo   string `json:"attached_to,omitempty"`
}

// --- JARM fingerprinting results ---

type JARMResult struct {
	Fingerprint string `json:"fingerprint"`
	Port        int    `json:"port,omitempty"` // port that produced the fingerprint
}

// --- UDP scan results ---

type UDPScanResult struct {
	OpenPorts []UDPPortInfo `json:"open_ports,omitempty"`
	ScanTime  string        `json:"scan_time,omitempty"`
}

type UDPPortInfo struct {
	Port          int    `json:"port"`
	Service       string `json:"service,omitempty"`
	ResponseSize  int    `json:"response_size,omitempty"`
	Amplification bool   `json:"amplification,omitempty"`
	AmpFactor     string `json:"amp_factor,omitempty"` // e.g., "4.2x"
}

// --- AlienVault OTX results ---

type AlienVaultResult struct {
	PulseCount int        `json:"pulse_count"`
	Reputation int        `json:"reputation,omitempty"`
	Country    string     `json:"country,omitempty"`
	ASN        string     `json:"asn,omitempty"`
	Link       string     `json:"link,omitempty"`
	Pulses     []OTXPulse `json:"pulses,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
}

type OTXPulse struct {
	Name     string   `json:"name"`
	Created  string   `json:"created,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Modified string   `json:"modified,omitempty"`
}

// --- Censys results ---

type CensysResult struct {
	Services        int             `json:"services"`
	LastUpdated     string          `json:"last_updated,omitempty"`
	OperatingSystem string          `json:"operating_system,omitempty"`
	ASN             int             `json:"asn,omitempty"`
	ASName          string          `json:"as_name,omitempty"`
	Country         string          `json:"country,omitempty"`
	Link            string          `json:"link,omitempty"`
	OpenPorts       []CensysService `json:"open_ports,omitempty"`
}

type CensysService struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Certificate string `json:"certificate,omitempty"` // subject CN
}

// --- IPinfo.io results ---

type IPInfoResult struct {
	Hostname       string `json:"hostname,omitempty"`
	City           string `json:"city,omitempty"`
	Region         string `json:"region,omitempty"`
	Country        string `json:"country,omitempty"`
	Loc            string `json:"loc,omitempty"` // lat,lon
	Org            string `json:"org,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	Postal         string `json:"postal,omitempty"`
	IsVPN          bool   `json:"is_vpn,omitempty"`
	IsProxy        bool   `json:"is_proxy,omitempty"`
	IsTor          bool   `json:"is_tor,omitempty"`
	IsRelay        bool   `json:"is_relay,omitempty"`
	IsHosting      bool   `json:"is_hosting,omitempty"`
	PrivacyService string `json:"privacy_service,omitempty"`
}

// --- ThreatFox (abuse.ch) results ---

type ThreatFoxResult struct {
	IOCCount        int            `json:"ioc_count"`
	Link            string         `json:"link,omitempty"`
	IOCs            []ThreatFoxIOC `json:"iocs,omitempty"`
	MalwareFamilies []string       `json:"malware_families,omitempty"`
	ThreatTypes     []string       `json:"threat_types,omitempty"`
}

type ThreatFoxIOC struct {
	Type         string   `json:"type,omitempty"`
	Malware      string   `json:"malware,omitempty"`
	MalwareAlias string   `json:"malware_alias,omitempty"`
	Confidence   int      `json:"confidence,omitempty"`
	FirstSeen    string   `json:"first_seen,omitempty"`
	LastSeen     string   `json:"last_seen,omitempty"`
	Reporter     string   `json:"reporter,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// --- Tech stack detection results ---

type TechStackResult struct {
	Technologies []TechMatch `json:"technologies,omitempty"`
	URL          string      `json:"url,omitempty"` // URL that was analyzed
}

type TechMatch struct {
	Name       string   `json:"name"`
	Categories []string `json:"categories,omitempty"`
	Version    string   `json:"version,omitempty"`
}

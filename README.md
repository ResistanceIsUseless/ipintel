# ipintel

Comprehensive IP intelligence from the command line. Takes an IP address (or domain, or file of targets) and runs concurrent OSINT lookups across 20+ providers, presenting results in a styled terminal report, JSON, Markdown, or CSV.

## Install

```sh
go install github.com/ResistanceIsUseless/ipintel/cmd/ipintel@latest
```

Or clone and build:

```sh
git clone https://github.com/ResistanceIsUseless/ipintel.git
cd ipintel
go build -o ipintel ./cmd/ipintel/
```

## Usage

```
ipintel [flags] <ip-address|domain>
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-json` | Output JSON (auto-disables spinner) |
| `-quiet` | Single-line grepable output (critical flags only) |
| `-no-spinner` | Disable animated spinner (for piping) |
| `-file <path>` | Read IPs/domains from file (one per line, `-` for stdin) |
| `-output-md <path>` | Write Markdown report to file |
| `-output-csv <path>` | Write CSV report to file |
| `-no-cache` | Disable result caching |
| `-no-aws` | Skip AWS tenant lookup |
| `-no-azure` | Skip Azure tenant lookup |
| `-no-gcp` | Skip GCP tenant lookup |
| `-version` | Show version |

**Examples:**

```sh
ipintel 1.1.1.1
ipintel --json 137.117.57.215
ipintel example.com
ipintel --file targets.txt --output-md report.md
cat ips.txt | ipintel --file - --quiet
ipintel --no-spinner 8.8.8.8 | less -R
```

## Configuration

Some providers require API keys or credentials. Set them via a `.env` file or environment variables:

```sh
cp .env.example .env
# Fill in your keys
```

### Threat Intelligence API Keys

All optional. The tool runs all free lookups without any configuration.

| Variable | Provider | Required |
|----------|----------|----------|
| `GREYNOISE_API_KEY` | GreyNoise | No |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | No |
| `SHODAN_API_KEY` | Shodan | No |
| `VIRUSTOTAL_API_KEY` | VirusTotal | No |
| `ALIENVAULT_API_KEY` | AlienVault OTX | No |
| `CENSYS_API_ID` | Censys | No |
| `CENSYS_API_SECRET` | Censys | No |
| `IPINFO_API_KEY` | IPinfo.io | No |

### Azure Tenant Lookup

Set `AZURE_SUBSCRIPTION_ID` to query your Azure subscription for public IP ownership. Authentication uses `DefaultAzureCredential` which tries, in order:

1. `az login` (easiest for local dev)
2. Environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`)
3. Managed identity (when running in Azure)

```sh
az login
export AZURE_SUBSCRIPTION_ID=your-subscription-id
ipintel 137.117.57.215
```

### AWS Tenant Lookup

Queries your AWS account for elastic/public IP ownership using `DescribeAddresses` and `DescribeNetworkInterfaces`. Authentication uses the default credential chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. `~/.aws/credentials` profile
3. Instance role (when running in AWS)

Set `AWS_TENANT_ENABLED=true` if using profile or instance auth without explicit keys.

```sh
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
ipintel 52.94.76.1
```

### GCP Tenant Lookup

Queries GCP projects for IP address ownership. Authentication uses Application Default Credentials:

```sh
gcloud auth application-default login
ipintel 34.120.0.1
```

## What It Does

Providers run in two phases. Phase 1 runs DNS and intelligence providers concurrently. Phase 2 runs hostname-aware providers (WebIntel, JARM, TechStack) with discovered hostnames for proper SNI and Host header routing.

**Network Identity**
- Reverse DNS (PTR)
- ASN lookup via Team Cymru DNS
- RDAP registration via IANA bootstrap (all 5 RIRs)
- Cloud provider detection (AWS, Azure, GCP) with service/region
- CDN/WAF detection via cdncheck

**DNS Intelligence**
- Reverse zone SOA/NS discovery
- Forward-Confirmed reverse DNS (FCrDNS)
- Authoritative vs recursive PTR comparison
- AXFR zone transfer attempt
- Iterative DNS trace from root servers
- Forward DNS recon on PTR hostnames (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV)

**Infrastructure**
- TCP port scan (24 common ports) with banner grabbing
- UDP scan (DNS, NTP, SNMP, IKE, SSDP, mDNS) with amplification detection
- TLS certificate metadata (CN, SANs, issuer, expiry) with hostname-aware SNI
- HTTP metadata (status, server, headers, redirects) with hostname-aware Host headers
- JARM TLS fingerprinting (10 probes) with hostname-aware SNI
- Tech stack detection via Wappalyzer signatures

**Threat Intelligence** (requires API keys)
- GreyNoise — internet scan classification
- AbuseIPDB — abuse reports and confidence score
- Shodan — open ports, vulns, OS fingerprinting
- VirusTotal — multi-engine detection, reputation, JARM fingerprint
- AlienVault OTX — pulse/IOC lookup
- Censys — host intelligence and service enumeration
- IPinfo.io — VPN/proxy/Tor/relay detection
- ThreatFox — abuse.ch IOC search

**Certificate Transparency**
- crt.sh lookup for issued certificates

**Cloud Tenant Lookups** (requires credentials)
- Azure — resolve IP to subscription, resource group, VM, load balancer, etc.
- AWS — resolve IP to EC2 instance, ENI, NAT gateway, NLB, etc. (multi-account via SSO)
- GCP — resolve IP to project, instance, forwarding rule, etc.

**Caching**
- File-based result cache (`~/.cache/ipintel/`, 24h TTL)
- Disable with `--no-cache`

## Architecture

```
cmd/ipintel/       CLI entrypoint, bulk processing, domain resolution
internal/
  cache/           File-based result cache (SHA256 keys, 24h TTL)
  config/          .env loader, config struct, Has*() guards
  lookup/          Provider interface + two-phase concurrent engine
    reverse_dns    PTR lookup
    dns_intel      SOA/NS, FCrDNS, AXFR, trace (miekg/dns)
    forward_dns    Record queries on PTR hostnames
    rdap           RDAP/ARIN registration (IANA bootstrap, all 5 RIRs)
    asn            Team Cymru DNS ASN lookup
    cloud          AWS/Azure/GCP IP range detection
    cdn            CDN/WAF detection (cdncheck)
    crtsh          crt.sh certificate transparency
    portscan       TCP connect scan + banners
    udpscan        UDP scan with amplification detection
    webintel       TLS cert + HTTP metadata (hostname-aware)
    jarm           JARM TLS fingerprinting (hostname-aware)
    techstack      Wappalyzer tech stack detection (hostname-aware)
    greynoise      GreyNoise API
    abuseipdb      AbuseIPDB API
    shodan         Shodan API
    virustotal     VirusTotal v3 API
    alienvault     AlienVault OTX API
    censys         Censys v2 API
    ipinfo         IPinfo.io API
    threatfox      ThreatFox (abuse.ch) API
    azure_tenant   Azure ARM public IP lookup
    aws_tenant     AWS EC2 describe addresses/ENIs (multi-account SSO)
    gcp_tenant     GCP Compute Engine IP lookup
  output/          Styled terminal renderer + JSON + Markdown + CSV + spinner
```

Each provider implements a `Provider` interface. Providers implementing `HostnameAwareProvider` receive discovered hostnames before execution for accurate SNI/Host header routing.

## License

MIT

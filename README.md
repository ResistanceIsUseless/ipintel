# ipintel

Comprehensive IP intelligence from the command line. Takes an IP address and runs concurrent OSINT lookups, presenting results in a styled terminal report or JSON.

## Install

```sh
go install github.com/mgriffiths/ipintel/cmd/ipintel@latest
```

Or clone and build:

```sh
git clone https://github.com/ResistanceIsUseless/ipintel.git
cd ipintel
go build -o ipintel ./cmd/ipintel/
```

## Usage

```
ipintel [flags] <ip-address>
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--json` | Output JSON (auto-disables spinner) |
| `--no-spinner` | Disable animated spinner (for piping) |
| `--version` | Show version |

**Examples:**

```sh
ipintel 1.1.1.1
ipintel --json 137.117.57.215
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

## What It Does

All providers run concurrently and results are displayed as they complete.

**Network Identity**
- Reverse DNS (PTR)
- ASN lookup via Team Cymru DNS
- RDAP/ARIN registration data
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
- TLS certificate metadata (CN, SANs, issuer, expiry)
- HTTP metadata (status, server, headers, redirects)

**Threat Intelligence** (requires API keys)
- GreyNoise — internet scan classification
- AbuseIPDB — abuse reports and confidence score
- Shodan — open ports, vulns, OS fingerprinting
- VirusTotal — multi-engine detection, reputation, JARM fingerprint

**Certificate Transparency**
- crt.sh lookup for issued certificates

**Cloud Tenant Lookups** (requires credentials)
- Azure — resolve IP to subscription, resource group, VM, load balancer, etc.
- AWS — resolve IP to EC2 instance, ENI, NAT gateway, NLB, etc.

## Architecture

```
cmd/ipintel/       CLI entrypoint
internal/
  config/          .env loader, config struct
  lookup/          Provider interface + concurrent engine
    reverse_dns    PTR lookup
    dns_intel      SOA/NS, FCrDNS, AXFR, trace (miekg/dns)
    forward_dns    Record queries on PTR hostnames
    rdap           RDAP/ARIN registration
    asn            Team Cymru DNS ASN lookup
    cloud          AWS/Azure/GCP IP range detection
    cdn            CDN/WAF detection (cdncheck)
    portscan       TCP connect scan + banners
    webintel       TLS cert + HTTP metadata
    greynoise      GreyNoise API
    abuseipdb      AbuseIPDB API
    shodan         Shodan API
    virustotal     VirusTotal v3 API
    azure_tenant   Azure ARM public IP lookup
    aws_tenant     AWS EC2 describe addresses/ENIs
    crtsh          crt.sh certificate transparency
  output/          Styled terminal renderer + JSON + spinner
```

Each provider implements a `Provider` interface and runs in parallel via the `Engine`.

## License

MIT

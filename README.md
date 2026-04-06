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

## API Keys

Some providers require API keys. Set them via a `.env` file or environment variables:

```sh
cp .env.example .env
# Fill in your keys
```

| Variable | Provider | Required |
|----------|----------|----------|
| `GREYNOISE_API_KEY` | GreyNoise | No |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | No |
| `SHODAN_API_KEY` | Shodan | No |

All API-key providers are optional. The tool runs all free lookups without any configuration.

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

**Infrastructure**
- TCP port scan (24 common ports) with banner grabbing
- TLS certificate metadata (CN, SANs, issuer, expiry)
- HTTP metadata (status, server, headers, redirects)

**Threat Intelligence** (requires API keys)
- GreyNoise — internet scan classification
- AbuseIPDB — abuse reports and confidence score
- Shodan — open ports, vulns, OS fingerprinting

**Certificate Transparency**
- crt.sh lookup for issued certificates

## Forward DNS Recon

When a PTR record is found, ipintel queries the hostname for A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, and SRV records — giving full DNS context for the host behind the IP.

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
    crtsh          crt.sh certificate transparency
  output/          Styled terminal renderer + JSON + spinner
```

Each provider implements a `Provider` interface and runs in parallel via the `Engine`.

## License

MIT

package lookup

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// WebIntel grabs TLS certificate info and HTTP metadata from open web ports.
// Implements HostnameAwareProvider to use discovered hostnames for SNI and Host headers.
type WebIntel struct {
	result    *WebIntelResult
	hostnames []string // set by engine phase-2 via SetHostnames
}

func NewWebIntel() *WebIntel {
	return &WebIntel{}
}

func (w *WebIntel) Name() string { return "web_intel" }

func (w *WebIntel) SetHostnames(hostnames []string) {
	w.hostnames = hostnames
}

func (w *WebIntel) Lookup(ctx context.Context, ip net.IP) error {
	w.result = &WebIntelResult{}

	// --- TLS probing ---
	// Try with raw IP first (no SNI)
	tlsInfo := probeTLS(ctx, ip, 443, "")
	if tlsInfo == nil {
		tlsInfo = probeTLS(ctx, ip, 8443, "")
	}

	// Try each discovered hostname with SNI — prefer the first one that yields
	// a different (potentially more specific) certificate
	for _, hostname := range w.hostnames {
		if sniTLS := probeTLS(ctx, ip, 443, hostname); sniTLS != nil {
			if tlsBetter(sniTLS, tlsInfo) {
				tlsInfo = sniTLS
				break
			}
		}
	}
	w.result.TLS = tlsInfo

	// --- HTTP probing ---
	// Try raw IP first
	httpInfo := probeHTTP(ctx, ip, true, 443, "")
	if httpInfo == nil {
		httpInfo = probeHTTP(ctx, ip, false, 80, "")
	}
	if httpInfo == nil {
		httpInfo = probeHTTP(ctx, ip, true, 8443, "")
	}
	if httpInfo == nil {
		httpInfo = probeHTTP(ctx, ip, false, 8080, "")
	}

	// Try with discovered hostnames — prefer the first one that gives a
	// non-default/richer response (e.g., a real page title, 200 instead of 4xx)
	for _, hostname := range w.hostnames {
		if hostHTTP := probeHTTP(ctx, ip, true, 443, hostname); hostHTTP != nil {
			if httpBetter(hostHTTP, httpInfo) {
				httpInfo = hostHTTP
				break
			}
		}
		if hostHTTP := probeHTTP(ctx, ip, false, 80, hostname); hostHTTP != nil {
			if httpBetter(hostHTTP, httpInfo) {
				httpInfo = hostHTTP
				break
			}
		}
	}
	w.result.HTTP = httpInfo

	// If we got nothing at all, don't bother applying
	if w.result.TLS == nil && w.result.HTTP == nil {
		w.result = nil
	}

	return nil
}

func (w *WebIntel) Apply(result *Result) {
	result.WebIntel = w.result
}

// tlsBetter returns true if candidate is a better TLS result than current.
// Prefers: non-nil over nil, non-expired over expired, more SANs.
func tlsBetter(candidate, current *TLSInfo) bool {
	if current == nil {
		return true
	}
	// Prefer non-expired certs
	if current.Expired && !candidate.Expired {
		return true
	}
	// Prefer certs with more SANs (likely the real service cert)
	if len(candidate.SANs) > len(current.SANs) {
		return true
	}
	return false
}

// httpBetter returns true if candidate is a better HTTP result than current.
// Prefers: non-nil over nil, 200 over non-200, responses with a title.
func httpBetter(candidate, current *HTTPInfo) bool {
	if current == nil {
		return true
	}
	// Prefer 200 OK over error codes
	if current.StatusCode != 200 && candidate.StatusCode == 200 {
		return true
	}
	// Prefer responses with a page title
	if current.Title == "" && candidate.Title != "" {
		return true
	}
	return false
}

// probeTLS connects to a port via TLS and extracts certificate info.
// If serverName is non-empty, it is set as SNI in the TLS Client Hello.
func probeTLS(ctx context.Context, ip net.IP, port int, serverName string) *TLSInfo {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // we want the cert even if it doesn't match
	}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}

	dialer := &tls.Dialer{
		Config: tlsCfg,
		NetDialer: &net.Dialer{
			Timeout: 5 * time.Second,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	cert := state.PeerCertificates[0]

	info := &TLSInfo{
		CommonName: cert.Subject.CommonName,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore.Format("2006-01-02"),
		NotAfter:   cert.NotAfter.Format("2006-01-02"),
		Expired:    cert.NotAfter.Before(time.Now()),
	}

	// SANs (limit to 20 to avoid flooding)
	for i, san := range cert.DNSNames {
		if i >= 20 {
			info.SANs = append(info.SANs, fmt.Sprintf("... +%d more", len(cert.DNSNames)-20))
			break
		}
		info.SANs = append(info.SANs, san)
	}

	// TLS version
	switch state.Version {
	case tls.VersionTLS10:
		info.Version = "TLS 1.0"
	case tls.VersionTLS11:
		info.Version = "TLS 1.1"
	case tls.VersionTLS12:
		info.Version = "TLS 1.2"
	case tls.VersionTLS13:
		info.Version = "TLS 1.3"
	default:
		info.Version = fmt.Sprintf("0x%04x", state.Version)
	}

	return info
}

// probeHTTP makes a GET request and extracts server info.
// If hostname is non-empty, the request URL uses the hostname (for proper
// virtual hosting) while a custom DialContext forces the TCP connection to
// the actual IP address.
func probeHTTP(ctx context.Context, ip net.IP, useTLS bool, port int, hostname string) *HTTPInfo {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	// Determine the host portion of the URL
	host := ip.String()
	if hostname != "" {
		host = hostname
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
	}

	// When using a hostname, force all TCP connections to go to the actual IP
	// so we probe the right server even though the URL has the hostname.
	if hostname != "" {
		ipAddr := ip.String()
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Replace the hostname:port with ip:port
			_, portStr, _ := net.SplitHostPort(addr)
			return (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext(ctx, network, net.JoinHostPort(ipAddr, portStr))
		}
		// Also set ServerName for TLS so the SNI matches the Host header
		transport.TLSClientConfig.ServerName = hostname
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		// Don't follow redirects - capture the redirect itself
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "ipintel/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	info := &HTTPInfo{
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
		Headers:    make(map[string]string),
	}

	// Capture redirect location
	if loc := resp.Header.Get("Location"); loc != "" {
		info.RedirectURL = loc
	}

	// Interesting security/info headers
	interestingHeaders := []string{
		"X-Frame-Options",
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Access-Control-Allow-Origin",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Generator",
		"X-Drupal-Cache",
		"X-Varnish",
		"Via",
		"X-Cache",
		"CF-RAY",
		"X-Amz-Cf-Id",
		"X-Azure-Ref",
	}

	for _, h := range interestingHeaders {
		if v := resp.Header.Get(h); v != "" {
			info.Headers[h] = v
		}
	}

	// Try to extract page title from body (limited read)
	if resp.StatusCode == 200 {
		info.Title = extractHTMLTitle(resp.Body)
	}

	return info
}

// extractHTMLTitle reads up to 64KB looking for a <title> tag.
func extractHTMLTitle(body io.Reader) string {
	limited := io.LimitReader(body, 64*1024)
	tokenizer := html.NewTokenizer(limited)

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return ""
		case html.StartTagToken:
			t := tokenizer.Token()
			if t.Data == "title" {
				if tokenizer.Next() == html.TextToken {
					title := strings.TrimSpace(tokenizer.Token().Data)
					if len(title) > 100 {
						title = title[:100] + "..."
					}
					return title
				}
			}
		}
	}
}

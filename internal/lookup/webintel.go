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
type WebIntel struct {
	result *WebIntelResult
}

func NewWebIntel() *WebIntel {
	return &WebIntel{}
}

func (w *WebIntel) Name() string { return "web_intel" }

func (w *WebIntel) Lookup(ctx context.Context, ip net.IP) error {
	w.result = &WebIntelResult{}

	// Try TLS on 443 first, fall back to 8443
	tlsInfo := probeTLS(ctx, ip, 443)
	if tlsInfo == nil {
		tlsInfo = probeTLS(ctx, ip, 8443)
	}
	w.result.TLS = tlsInfo

	// Try HTTP(S) metadata
	httpInfo := probeHTTP(ctx, ip, true, 443) // HTTPS first
	if httpInfo == nil {
		httpInfo = probeHTTP(ctx, ip, false, 80) // fallback to HTTP
	}
	if httpInfo == nil {
		httpInfo = probeHTTP(ctx, ip, true, 8443)
	}
	if httpInfo == nil {
		httpInfo = probeHTTP(ctx, ip, false, 8080)
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

// probeTLS connects to a port via TLS and extracts certificate info.
func probeTLS(ctx context.Context, ip net.IP, port int) *TLSInfo {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // we want the cert even if it doesn't match
		},
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

// probeHTTP makes a HEAD/GET request and extracts server info.
func probeHTTP(ctx context.Context, ip net.IP, useTLS bool, port int) *HTTPInfo {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, ip.String(), port)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
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

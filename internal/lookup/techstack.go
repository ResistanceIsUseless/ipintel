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

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// TechStackDetector uses Wappalyzer signatures to identify technologies
// from HTTP responses (headers, body, cookies, scripts, meta tags).
// Implements HostnameAwareProvider to use discovered hostnames for proper
// Host headers, which reveals the real application behind virtual hosting.
type TechStackDetector struct {
	result    *TechStackResult
	hostnames []string // set by engine phase-2 via SetHostnames
}

func NewTechStackDetector() *TechStackDetector {
	return &TechStackDetector{}
}

func (t *TechStackDetector) Name() string { return "tech-stack" }

func (t *TechStackDetector) SetHostnames(hostnames []string) {
	t.hostnames = hostnames
}

func (t *TechStackDetector) Lookup(ctx context.Context, ip net.IP) error {
	wap, err := wappalyzer.New()
	if err != nil {
		return fmt.Errorf("wappalyzer init: %w", err)
	}

	// Try with discovered hostnames first (most likely to get the real application),
	// then fall back to raw IP
	targets := t.buildTargets(ip)

	for _, target := range targets {
		resp, body, targetURL, fetchErr := t.fetchTarget(ctx, ip, target)
		if fetchErr != nil || resp == nil {
			continue
		}

		// Build headers map for wappalyzer
		headers := make(map[string][]string)
		for k, v := range resp.Header {
			headers[k] = v
		}

		// Run fingerprinting with app info (includes categories)
		fingerprints := wap.FingerprintWithInfo(headers, body)
		if len(fingerprints) == 0 {
			continue
		}

		t.result = &TechStackResult{
			URL: targetURL,
		}

		for name, info := range fingerprints {
			// Wappalyzer encodes version as "name:version" in the key
			techName := name
			version := ""
			if parts := strings.SplitN(name, ":", 2); len(parts) == 2 {
				techName = parts[0]
				version = parts[1]
			}

			match := TechMatch{
				Name:       techName,
				Categories: info.Categories,
				Version:    version,
			}
			t.result.Technologies = append(t.result.Technologies, match)
		}

		// Got results — use this target
		return nil
	}

	return nil
}

// buildTargets returns an ordered list of targets to probe. Hostnames come
// first (most likely to reveal the real application), then the raw IP.
func (t *TechStackDetector) buildTargets(ip net.IP) []string {
	var targets []string
	for _, h := range t.hostnames {
		targets = append(targets, h)
	}
	targets = append(targets, ip.String())
	return targets
}

// fetchTarget tries HTTPS then HTTP for the given target host.
// If target differs from ip.String(), a custom DialContext forces TCP
// connections to the actual IP while the URL/Host header uses the hostname.
func (t *TechStackDetector) fetchTarget(ctx context.Context, ip net.IP, target string) (*http.Response, []byte, string, error) {
	isHostname := target != ip.String()

	for _, scheme := range []string{"https", "http"} {
		targetURL := fmt.Sprintf("%s://%s/", scheme, target)

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		// When probing via hostname, force TCP connections to the actual IP
		if isHostname {
			ipAddr := ip.String()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, portStr, _ := net.SplitHostPort(addr)
				return (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext(ctx, network, net.JoinHostPort(ipAddr, portStr))
			}
			transport.TLSClientConfig.ServerName = target
		}

		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ipintel/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read up to 1MB of body for analysis
		limited := io.LimitReader(resp.Body, 1<<20)
		body, err := io.ReadAll(limited)
		if err != nil {
			continue
		}

		return resp, body, targetURL, nil
	}

	return nil, nil, "", fmt.Errorf("no response from %s", target)
}

func (t *TechStackDetector) Apply(result *Result) {
	if t.result != nil {
		result.TechStack = t.result
	}
}

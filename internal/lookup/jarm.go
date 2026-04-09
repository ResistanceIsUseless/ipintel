package lookup

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// JARMScanner performs active JARM TLS fingerprinting.
// JARM works by sending 10 crafted TLS Client Hello packets with varying
// parameters and hashing the Server Hello responses to produce a unique fingerprint.
// Implements HostnameAwareProvider to set SNI in TLS probes for accurate fingerprinting
// on multi-tenant/SNI-routed servers.
type JARMScanner struct {
	result    *JARMResult
	hostnames []string // set by engine phase-2 via SetHostnames
}

func NewJARMScanner() *JARMScanner {
	return &JARMScanner{}
}

func (j *JARMScanner) Name() string { return "jarm" }

func (j *JARMScanner) SetHostnames(hostnames []string) {
	j.hostnames = hostnames
}

func (j *JARMScanner) Lookup(ctx context.Context, ip net.IP) error {
	// Scan common TLS ports
	ports := []int{443, 8443, 8080, 4443}
	ipStr := ip.String()

	// Determine the best SNI to use — first discovered hostname, or empty for IP-only
	serverName := ""
	if len(j.hostnames) > 0 {
		serverName = j.hostnames[0]
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Try with hostname SNI first (if available)
		if serverName != "" {
			fingerprint := jarmScanPort(ctx, ipStr, port, serverName)
			if fingerprint != "" && !isEmptyJARM(fingerprint) {
				j.result = &JARMResult{
					Fingerprint: fingerprint,
					Port:        port,
				}
				return nil
			}
		}

		// Fall back to IP-only (no SNI)
		fingerprint := jarmScanPort(ctx, ipStr, port, "")
		if fingerprint != "" && !isEmptyJARM(fingerprint) {
			j.result = &JARMResult{
				Fingerprint: fingerprint,
				Port:        port,
			}
			return nil
		}
	}

	return nil
}

func (j *JARMScanner) Apply(result *Result) {
	if j.result != nil {
		result.JARM = j.result
	}
}

// jarmScanPort performs a simplified JARM-style fingerprint on a single port.
// A full JARM implementation sends 10 different Client Hello probes. This
// implementation sends probes with varying TLS versions and cipher suites
// to build a composite fingerprint. If serverName is non-empty, it is set
// as SNI in each TLS probe.
func jarmScanPort(ctx context.Context, host string, port int, serverName string) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// JARM probes: each uses different TLS min/max versions and cipher orderings
	type probe struct {
		minVer  uint16
		maxVer  uint16
		ciphers []uint16
	}

	probes := []probe{
		{tls.VersionTLS12, tls.VersionTLS13, nil},                   // default
		{tls.VersionTLS12, tls.VersionTLS12, nil},                   // TLS 1.2 only
		{tls.VersionTLS11, tls.VersionTLS12, nil},                   // 1.1-1.2
		{tls.VersionTLS10, tls.VersionTLS12, nil},                   // 1.0-1.2
		{tls.VersionTLS13, tls.VersionTLS13, nil},                   // TLS 1.3 only
		{tls.VersionTLS12, tls.VersionTLS12, jarmReversedCiphers()}, // reversed ciphers
		{tls.VersionTLS12, tls.VersionTLS12, jarmForwardCiphers()},  // forward ciphers
		{tls.VersionTLS12, tls.VersionTLS13, jarmReversedCiphers()}, // reversed + 1.3
		{tls.VersionTLS10, tls.VersionTLS13, nil},                   // widest range
		{tls.VersionTLS12, tls.VersionTLS12, jarmMinimalCiphers()},  // minimal ciphers
	}

	var parts []string
	for _, p := range probes {
		select {
		case <-ctx.Done():
			return ""
		default:
		}

		result := jarmProbe(ctx, addr, p.minVer, p.maxVer, p.ciphers, serverName)
		parts = append(parts, result)
	}

	return strings.Join(parts, "|")
}

// jarmProbe sends a single TLS Client Hello and returns a short hash of the Server Hello response.
// If serverName is non-empty, it is set as SNI in the TLS config.
func jarmProbe(ctx context.Context, addr string, minVer, maxVer uint16, ciphers []uint16, serverName string) string {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "0"
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         minVer,
		MaxVersion:         maxVer,
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	if len(ciphers) > 0 {
		cfg.CipherSuites = ciphers
	}

	tlsConn := tls.Client(conn, cfg)
	err = tlsConn.HandshakeContext(ctx)

	if err != nil {
		// Connection refused or handshake failed — this is still a signal
		return "0"
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()

	// Build a fingerprint component from the negotiated parameters
	return fmt.Sprintf("%04x-%04x-%x",
		state.Version,
		state.CipherSuite,
		boolToInt(state.NegotiatedProtocolIsMutual))
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// jarmReversedCiphers returns common cipher suites in reverse order.
func jarmReversedCiphers() []uint16 {
	suites := jarmForwardCiphers()
	for i, j := 0, len(suites)-1; i < j; i, j = i+1, j-1 {
		suites[i], suites[j] = suites[j], suites[i]
	}
	return suites
}

// jarmForwardCiphers returns common cipher suites in standard order.
func jarmForwardCiphers() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	}
}

// jarmMinimalCiphers returns a minimal cipher suite set.
func jarmMinimalCiphers() []uint16 {
	return []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
}

func isEmptyJARM(fingerprint string) bool {
	// All zeros means no responses
	cleaned := strings.ReplaceAll(fingerprint, "0", "")
	cleaned = strings.ReplaceAll(cleaned, "|", "")
	return cleaned == ""
}

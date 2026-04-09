package lookup

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// PortScanner performs a quick TCP connect scan on common service ports.
type PortScanner struct {
	result *PortScanResult
}

func NewPortScanner() *PortScanner {
	return &PortScanner{}
}

func (p *PortScanner) Name() string { return "port_scan" }

// commonPorts maps port numbers to likely service names.
var commonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1521:  "Oracle",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	9200:  "Elasticsearch",
	9443:  "VSphere",
	27017: "MongoDB",
}

func (p *PortScanner) Lookup(ctx context.Context, ip net.IP) error {
	start := time.Now()

	var (
		openPorts []PortInfo
		mu        sync.Mutex
		wg        sync.WaitGroup
	)

	// Use a semaphore to limit concurrency
	sem := make(chan struct{}, 20)

	for port, service := range commonPorts {
		wg.Add(1)
		go func(port int, service string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := probePort(ctx, ip, port, service)
			if info != nil {
				mu.Lock()
				openPorts = append(openPorts, *info)
				mu.Unlock()
			}
		}(port, service)
	}

	wg.Wait()

	// Sort by port number
	sortPorts(openPorts)

	p.result = &PortScanResult{
		OpenPorts: openPorts,
		ScanTime:  fmt.Sprintf("%dms", time.Since(start).Milliseconds()),
	}

	return nil
}

func (p *PortScanner) Apply(result *Result) {
	result.Ports = p.result
}

func probePort(ctx context.Context, ip net.IP, port int, service string) *PortInfo {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	info := &PortInfo{
		Port:     port,
		Protocol: "tcp",
		Service:  service,
	}

	// Try to grab a banner for text-based protocols
	if isBannerPort(port) {
		banner := grabBanner(conn)
		if banner != "" {
			info.Banner = banner
		}
	}

	return info
}

func isBannerPort(port int) bool {
	switch port {
	case 21, 22, 25, 110, 143, 993, 995:
		return true
	}
	return false
}

func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	line = strings.TrimSpace(line)
	// Truncate long banners
	if len(line) > 200 {
		line = line[:200] + "..."
	}
	return line
}

func sortPorts(ports []PortInfo) {
	for i := 1; i < len(ports); i++ {
		key := ports[i]
		j := i - 1
		for j >= 0 && ports[j].Port > key.Port {
			ports[j+1] = ports[j]
			j--
		}
		ports[j+1] = key
	}
}

package lookup

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDPScanner performs lightweight UDP probing on common reflection/amplification ports.
type UDPScanner struct {
	result *UDPScanResult
}

func NewUDPScanner() *UDPScanner {
	return &UDPScanner{}
}

func (u *UDPScanner) Name() string { return "udp_scan" }

// udpProbes defines UDP services to probe with their trigger packets.
var udpProbes = map[int]udpProbe{
	53:   {Service: "DNS", Payload: dnsProbePacket()},
	123:  {Service: "NTP", Payload: ntpProbePacket()},
	161:  {Service: "SNMP", Payload: snmpProbePacket()},
	500:  {Service: "IKE", Payload: ikeProbePacket()},
	1900: {Service: "SSDP", Payload: ssdpProbePacket()},
	5353: {Service: "mDNS", Payload: dnsProbePacket()},
}

type udpProbe struct {
	Service string
	Payload []byte
}

func (u *UDPScanner) Lookup(ctx context.Context, ip net.IP) error {
	start := time.Now()

	var (
		openPorts []UDPPortInfo
		mu        sync.Mutex
		wg        sync.WaitGroup
	)

	for port, probe := range udpProbes {
		wg.Add(1)
		go func(port int, probe udpProbe) {
			defer wg.Done()

			if info := probeUDP(ctx, ip, port, probe); info != nil {
				mu.Lock()
				openPorts = append(openPorts, *info)
				mu.Unlock()
			}
		}(port, probe)
	}

	wg.Wait()

	// Sort by port
	sortUDPPorts(openPorts)

	u.result = &UDPScanResult{
		OpenPorts: openPorts,
		ScanTime:  fmt.Sprintf("%dms", time.Since(start).Milliseconds()),
	}

	return nil
}

func (u *UDPScanner) Apply(result *Result) {
	if u.result != nil && len(u.result.OpenPorts) > 0 {
		result.UDPScan = u.result
	}
}

func probeUDP(ctx context.Context, ip net.IP, port int, probe udpProbe) *UDPPortInfo {
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(probe.Payload); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil // timeout = likely filtered/closed
	}

	info := &UDPPortInfo{
		Port:         port,
		Service:      probe.Service,
		ResponseSize: n,
	}

	// Check for amplification potential (response larger than request)
	if n > len(probe.Payload) {
		info.Amplification = true
		info.AmpFactor = fmt.Sprintf("%.1fx", float64(n)/float64(len(probe.Payload)))
	}

	return info
}

// --- Probe packet constructors ---

// dnsProbePacket creates a minimal DNS query for version.bind (common for fingerprinting).
func dnsProbePacket() []byte {
	// Standard DNS query for version.bind TXT CH
	return []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Standard query, recursion desired
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		// Query: version.bind IN TXT CH
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
		0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
		0x00,       // root
		0x00, 0x10, // Type: TXT
		0x00, 0x03, // Class: CH
	}
}

// ntpProbePacket creates an NTP version request (mode 3, client).
func ntpProbePacket() []byte {
	pkt := make([]byte, 48)
	pkt[0] = 0x1B // LI=0, VN=3, Mode=3 (client)
	return pkt
}

// snmpProbePacket creates an SNMPv1 GetRequest for sysDescr.
func snmpProbePacket() []byte {
	return []byte{
		0x30, 0x26, // SEQUENCE, length 38
		0x02, 0x01, 0x01, // INTEGER: version = 1 (SNMPv2c)
		0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING: "public"
		0xa0, 0x19, // GetRequest PDU
		0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id
		0x02, 0x01, 0x00, // error-status: 0
		0x02, 0x01, 0x00, // error-index: 0
		0x30, 0x0b, // variable-bindings
		0x30, 0x09,
		0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1 (sysDescr)
		0x05, 0x00, // NULL
	}
}

// ikeProbePacket creates a minimal IKEv1 Main Mode SA proposal.
func ikeProbePacket() []byte {
	return []byte{
		// Initiator cookie (8 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		// Responder cookie (8 bytes, zeros for initial)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Next payload: SA (1)
		0x01,
		// Version: 1.0
		0x10,
		// Exchange type: Main Mode (2)
		0x02,
		// Flags
		0x00,
		// Message ID
		0x00, 0x00, 0x00, 0x00,
		// Length (28 bytes total)
		0x00, 0x00, 0x00, 0x1c,
	}
}

// ssdpProbePacket creates an SSDP M-SEARCH discovery request.
func ssdpProbePacket() []byte {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"
	return []byte(msg)
}

func sortUDPPorts(ports []UDPPortInfo) {
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

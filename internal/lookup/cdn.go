package lookup

import (
	"context"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

// CDNDetector checks if an IP belongs to a known CDN, WAF, or cloud provider
// using projectdiscovery's cdncheck library.
type CDNDetector struct {
	result *CDNResult
}

func NewCDNDetector() *CDNDetector {
	return &CDNDetector{}
}

func (c *CDNDetector) Name() string { return "cdn_waf" }

func (c *CDNDetector) Lookup(ctx context.Context, ip net.IP) error {
	client := cdncheck.New()

	// Check() returns matched, value (provider name), itemType (cdn/waf/cloud), err
	matched, value, itemType, err := client.Check(ip)
	if err != nil {
		return nil // non-fatal, just means no match
	}

	if matched {
		category := "Unknown"
		switch itemType {
		case "cdn":
			category = "CDN"
		case "waf":
			category = "WAF"
		case "cloud":
			category = "Cloud"
		}

		c.result = &CDNResult{
			Detected: true,
			Name:     value,
			Type:     itemType,
			Category: category,
		}
	}

	return nil
}

func (c *CDNDetector) Apply(result *Result) {
	if c.result != nil {
		result.CDN = c.result
	}
}

package lookup

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// CloudDetector checks if an IP belongs to a known cloud provider.
type CloudDetector struct {
	result *CloudResult
}

func NewCloudDetector() *CloudDetector {
	return &CloudDetector{}
}

func (c *CloudDetector) Name() string { return "cloud_detect" }

func (c *CloudDetector) Lookup(ctx context.Context, ip net.IP) error {
	type match struct {
		provider string
		service  string
		region   string
		cidr     string
	}

	results := make(chan *match, 3)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if m := checkAWS(ctx, ip); m != nil {
			results <- &match{provider: "AWS", service: m.service, region: m.region, cidr: m.cidr}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if m := checkAzure(ctx, ip); m != nil {
			results <- &match{provider: "Azure", service: m.service, region: m.region, cidr: m.cidr}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if m := checkGCP(ctx, ip); m != nil {
			results <- &match{provider: "GCP", service: m.service, region: m.region, cidr: m.cidr}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for m := range results {
		c.result = &CloudResult{
			Provider:    m.provider,
			Service:     m.service,
			Region:      m.region,
			NetworkCIDR: m.cidr,
		}
		return nil
	}

	return nil
}

func (c *CloudDetector) Apply(result *Result) {
	result.Cloud = c.result
}

type cloudMatch struct {
	service string
	region  string
	cidr    string
}

// --- AWS ---

var (
	awsRangesOnce sync.Once
	awsRanges     *awsIPRanges
)

type awsIPRanges struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
		Region   string `json:"region"`
		Service  string `json:"service"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Region     string `json:"region"`
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"`
}

func fetchAWSRanges(ctx context.Context) *awsIPRanges {
	awsRangesOnce.Do(func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://ip-ranges.amazonaws.com/ip-ranges.json", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		var ranges awsIPRanges
		if json.Unmarshal(body, &ranges) == nil {
			awsRanges = &ranges
		}
	})
	return awsRanges
}

func checkAWS(ctx context.Context, ip net.IP) *cloudMatch {
	ranges := fetchAWSRanges(ctx)
	if ranges == nil {
		return nil
	}

	isV4 := ip.To4() != nil
	if isV4 {
		for _, prefix := range ranges.Prefixes {
			_, network, err := net.ParseCIDR(prefix.IPPrefix)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return &cloudMatch{service: prefix.Service, region: prefix.Region, cidr: prefix.IPPrefix}
			}
		}
	} else {
		for _, prefix := range ranges.IPv6Prefixes {
			_, network, err := net.ParseCIDR(prefix.IPv6Prefix)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return &cloudMatch{service: prefix.Service, region: prefix.Region, cidr: prefix.IPv6Prefix}
			}
		}
	}
	return nil
}

// --- Azure ---

var (
	azureRangesOnce sync.Once
	azureRanges     *azureIPRanges
)

type azureIPRanges struct {
	Values []struct {
		Name       string `json:"name"`
		Properties struct {
			Region          string   `json:"region"`
			Platform        string   `json:"platform"`
			SystemService   string   `json:"systemService"`
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	} `json:"values"`
}

func fetchAzureRanges(ctx context.Context) *azureIPRanges {
	azureRangesOnce.Do(func() {
		pageReq, _ := http.NewRequestWithContext(ctx, "GET",
			"https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519", nil)
		pageResp, err := http.DefaultClient.Do(pageReq)
		if err != nil {
			return
		}
		defer pageResp.Body.Close()
		pageBody, _ := io.ReadAll(pageResp.Body)

		downloadURL := extractAzureDownloadURL(string(pageBody))
		if downloadURL == "" {
			return
		}

		req, _ := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var ranges azureIPRanges
		if json.Unmarshal(body, &ranges) == nil {
			azureRanges = &ranges
		}
	})
	return azureRanges
}

func extractAzureDownloadURL(page string) string {
	marker := "https://download.microsoft.com/download/"
	idx := strings.Index(page, marker)
	if idx < 0 {
		return ""
	}
	end := strings.IndexAny(page[idx:], "\"' ")
	if end < 0 {
		return ""
	}
	return page[idx : idx+end]
}

func checkAzure(ctx context.Context, ip net.IP) *cloudMatch {
	ranges := fetchAzureRanges(ctx)
	if ranges == nil {
		return nil
	}

	for _, val := range ranges.Values {
		for _, prefix := range val.Properties.AddressPrefixes {
			_, network, err := net.ParseCIDR(prefix)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				service := val.Properties.SystemService
				if service == "" {
					service = val.Name
				}
				return &cloudMatch{service: service, region: val.Properties.Region, cidr: prefix}
			}
		}
	}
	return nil
}

// --- GCP ---

var (
	gcpRangesOnce sync.Once
	gcpRanges     *gcpIPRanges
)

type gcpIPRanges struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
		Service    string `json:"service"`
		Scope      string `json:"scope"`
	} `json:"prefixes"`
}

func fetchGCPRanges(ctx context.Context) *gcpIPRanges {
	gcpRangesOnce.Do(func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.gstatic.com/ipranges/cloud.json", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var ranges gcpIPRanges
		if json.Unmarshal(body, &ranges) == nil {
			gcpRanges = &ranges
		}
	})
	return gcpRanges
}

func checkGCP(ctx context.Context, ip net.IP) *cloudMatch {
	ranges := fetchGCPRanges(ctx)
	if ranges == nil {
		return nil
	}

	isV4 := ip.To4() != nil
	for _, prefix := range ranges.Prefixes {
		cidr := prefix.IPv4Prefix
		if !isV4 {
			cidr = prefix.IPv6Prefix
		}
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return &cloudMatch{service: prefix.Service, region: prefix.Scope, cidr: cidr}
		}
	}
	return nil
}

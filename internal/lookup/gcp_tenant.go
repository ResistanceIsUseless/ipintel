package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GCPTenantConfig holds configuration for the GCP tenant lookup.
type GCPTenantConfig struct {
	Projects []string // explicit project IDs to search (empty = discover via resource manager)
	Regions  []string // regions to search (empty = all major regions)
}

// GCPTenant searches GCP Compute Engine for IP allocations.
// Requires Application Default Credentials (gcloud auth application-default login).
type GCPTenant struct {
	cfg    GCPTenantConfig
	result *GCPTenantResult
}

func NewGCPTenant(cfg GCPTenantConfig) *GCPTenant {
	return &GCPTenant{cfg: cfg}
}

func (g *GCPTenant) Name() string { return "gcp_tenant" }

func (g *GCPTenant) SupportsPrivateIP() bool { return true }

// gcpDefaultRegions covers the major GCP regions.
var gcpDefaultRegions = []string{
	"us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
	"europe-west1", "europe-west2", "europe-west3", "europe-west4",
	"asia-east1", "asia-southeast1", "asia-northeast1",
	"australia-southeast1", "southamerica-east1",
}

func (g *GCPTenant) Lookup(ctx context.Context, ip net.IP) error {
	token, err := gcpGetAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("GCP auth failed: %w", err)
	}

	projects := g.cfg.Projects
	if len(projects) == 0 {
		projects, err = gcpListProjects(ctx, token)
		if err != nil {
			return fmt.Errorf("GCP project discovery failed: %w", err)
		}
	}
	if len(projects) == 0 {
		return nil
	}

	regions := g.cfg.Regions
	if len(regions) == 0 {
		regions = gcpDefaultRegions
	}

	ipStr := ip.String()
	isPrivate := ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()

	resultCh := make(chan *GCPTenantResult, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, project := range projects {
		wg.Add(1)
		go func(proj string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check global static addresses (external IPs)
			if !isPrivate {
				if r := gcpCheckGlobalAddresses(ctx, token, proj, ipStr); r != nil {
					select {
					case resultCh <- r:
						cancel()
					default:
					}
					return
				}
			}

			// Check regional addresses and instances
			for _, region := range regions {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if !isPrivate {
					if r := gcpCheckRegionalAddresses(ctx, token, proj, region, ipStr); r != nil {
						select {
						case resultCh <- r:
							cancel()
						default:
						}
						return
					}
				}

				if r := gcpCheckInstances(ctx, token, proj, region, ipStr, isPrivate); r != nil {
					select {
					case resultCh <- r:
						cancel()
					default:
					}
					return
				}

				if !isPrivate {
					if r := gcpCheckForwardingRules(ctx, token, proj, region, ipStr); r != nil {
						select {
						case resultCh <- r:
							cancel()
						default:
						}
						return
					}
				}
			}
		}(project)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if r, ok := <-resultCh; ok {
		g.result = r
	} else {
		g.result = &GCPTenantResult{Found: false}
	}

	return nil
}

func (g *GCPTenant) Apply(result *Result) {
	if g.result != nil {
		result.GCPTenant = g.result
	}
}

// --- GCP Auth ---

// gcpGetAccessToken retrieves an access token via metadata server or ADC file.
func gcpGetAccessToken(ctx context.Context) (string, error) {
	// Try metadata server first (GCE/Cloud Shell/Cloud Run)
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	if resp, err := client.Do(req); err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			var tok struct {
				AccessToken string `json:"access_token"`
			}
			if json.NewDecoder(resp.Body).Decode(&tok) == nil && tok.AccessToken != "" {
				return tok.AccessToken, nil
			}
		}
	}

	// Fall back to application default credentials
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	adcPath := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	data, err := os.ReadFile(adcPath)
	if err != nil {
		return "", fmt.Errorf("no application default credentials (run: gcloud auth application-default login): %w", err)
	}

	var adc struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"type"`
	}
	if err := json.Unmarshal(data, &adc); err != nil {
		return "", fmt.Errorf("invalid ADC file: %w", err)
	}
	if adc.Type != "authorized_user" || adc.RefreshToken == "" {
		return "", fmt.Errorf("unsupported ADC type: %s (run: gcloud auth application-default login)", adc.Type)
	}

	// Exchange refresh token for access token
	body := fmt.Sprintf("client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token",
		adc.ClientID, adc.ClientSecret, adc.RefreshToken)

	tokenClient := &http.Client{Timeout: 10 * time.Second}
	tokenReq, err := http.NewRequestWithContext(ctx, "POST",
		"https://oauth2.googleapis.com/token",
		strings.NewReader(body))
	if err != nil {
		return "", err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tokenClient.Do(tokenReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Error != "" {
		return "", fmt.Errorf("token exchange failed: %s", tok.Error)
	}
	return tok.AccessToken, nil
}

// --- GCP API Helpers ---

func gcpListProjects(ctx context.Context, token string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState%3DACTIVE&pageSize=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("project list failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Projects []struct {
			ProjectID string `json:"projectId"`
		} `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	projects := make([]string, len(result.Projects))
	for i, p := range result.Projects {
		projects[i] = p.ProjectID
	}
	return projects, nil
}

func gcpAPIGet(ctx context.Context, token, url string) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// --- GCP Resource Checks ---

func gcpCheckGlobalAddresses(ctx context.Context, token, project, ip string) *GCPTenantResult {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/addresses", project)
	data, err := gcpAPIGet(ctx, token, url)
	if err != nil {
		return nil
	}

	var resp struct {
		Items []struct {
			Name        string   `json:"name"`
			Address     string   `json:"address"`
			Status      string   `json:"status"`
			AddressType string   `json:"addressType"`
			Users       []string `json:"users"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &resp) != nil {
		return nil
	}

	for _, addr := range resp.Items {
		if addr.Address == ip {
			r := &GCPTenantResult{
				Found:     true,
				ProjectID: project,
				IPName:    addr.Name,
				IPType:    addr.AddressType,
				Status:    addr.Status,
				Scope:     "global",
			}
			if len(addr.Users) > 0 {
				r.AttachedTo = gcpExtractResourceName(addr.Users[0])
				r.ResourceType = gcpClassifyResource(addr.Users[0])
			}
			return r
		}
	}
	return nil
}

func gcpCheckRegionalAddresses(ctx context.Context, token, project, region, ip string) *GCPTenantResult {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/regions/%s/addresses", project, region)
	data, err := gcpAPIGet(ctx, token, url)
	if err != nil {
		return nil
	}

	var resp struct {
		Items []struct {
			Name        string   `json:"name"`
			Address     string   `json:"address"`
			Status      string   `json:"status"`
			AddressType string   `json:"addressType"`
			Subnetwork  string   `json:"subnetwork"`
			Users       []string `json:"users"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &resp) != nil {
		return nil
	}

	for _, addr := range resp.Items {
		if addr.Address == ip {
			r := &GCPTenantResult{
				Found:     true,
				ProjectID: project,
				Region:    region,
				IPName:    addr.Name,
				IPType:    addr.AddressType,
				Status:    addr.Status,
				Scope:     "regional",
				Subnet:    gcpExtractResourceName(addr.Subnetwork),
			}
			if len(addr.Users) > 0 {
				r.AttachedTo = gcpExtractResourceName(addr.Users[0])
				r.ResourceType = gcpClassifyResource(addr.Users[0])
			}
			return r
		}
	}
	return nil
}

func gcpCheckInstances(ctx context.Context, token, project, region, ip string, isPrivate bool) *GCPTenantResult {
	zones := []string{region + "-a", region + "-b", region + "-c"}

	for _, zone := range zones {
		url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances", project, zone)
		data, err := gcpAPIGet(ctx, token, url)
		if err != nil {
			continue
		}

		var resp struct {
			Items []struct {
				Name              string `json:"name"`
				Status            string `json:"status"`
				NetworkInterfaces []struct {
					NetworkIP     string `json:"networkIP"`
					Network       string `json:"network"`
					Subnetwork    string `json:"subnetwork"`
					AccessConfigs []struct {
						NatIP string `json:"natIP"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
			} `json:"items"`
		}
		if json.Unmarshal(data, &resp) != nil {
			continue
		}

		for _, inst := range resp.Items {
			for _, nic := range inst.NetworkInterfaces {
				if isPrivate && nic.NetworkIP == ip {
					return &GCPTenantResult{
						Found:        true,
						ProjectID:    project,
						Region:       region,
						Zone:         zone,
						InstanceName: inst.Name,
						PrivateIP:    nic.NetworkIP,
						ResourceType: "VM Instance",
						Network:      gcpExtractResourceName(nic.Network),
						Subnet:       gcpExtractResourceName(nic.Subnetwork),
						Status:       inst.Status,
					}
				}
				for _, ac := range nic.AccessConfigs {
					if !isPrivate && ac.NatIP == ip {
						return &GCPTenantResult{
							Found:        true,
							ProjectID:    project,
							Region:       region,
							Zone:         zone,
							InstanceName: inst.Name,
							PublicIP:     ac.NatIP,
							PrivateIP:    nic.NetworkIP,
							ResourceType: "VM Instance",
							Network:      gcpExtractResourceName(nic.Network),
							Subnet:       gcpExtractResourceName(nic.Subnetwork),
							Status:       inst.Status,
						}
					}
				}
			}
		}
	}
	return nil
}

func gcpCheckForwardingRules(ctx context.Context, token, project, region, ip string) *GCPTenantResult {
	url := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/regions/%s/forwardingRules", project, region)
	data, err := gcpAPIGet(ctx, token, url)
	if err != nil {
		return nil
	}

	var resp struct {
		Items []struct {
			Name      string `json:"name"`
			IPAddress string `json:"IPAddress"`
			Target    string `json:"target"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &resp) != nil {
		return nil
	}

	for _, rule := range resp.Items {
		if rule.IPAddress == ip {
			return &GCPTenantResult{
				Found:        true,
				ProjectID:    project,
				Region:       region,
				PublicIP:     ip,
				ResourceType: "Load Balancer",
				AttachedTo:   gcpExtractResourceName(rule.Target),
				IPName:       rule.Name,
			}
		}
	}
	return nil
}

func gcpExtractResourceName(url string) string {
	if url == "" {
		return ""
	}
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return url
}

func gcpClassifyResource(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "/instances/"):
		return "VM Instance"
	case strings.Contains(lower, "/forwardingrules/") || strings.Contains(lower, "/targetpools/"):
		return "Load Balancer"
	case strings.Contains(lower, "/routers/"):
		return "Cloud Router"
	case strings.Contains(lower, "/vpngateways/"):
		return "VPN Gateway"
	default:
		return "Compute Resource"
	}
}

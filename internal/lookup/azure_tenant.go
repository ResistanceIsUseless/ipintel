package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// AzureTenant queries all Azure subscriptions the caller has access to
// using Azure Resource Graph for fast, indexed cross-subscription IP search.
type AzureTenant struct {
	result *AzureTenantResult
}

func NewAzureTenant() *AzureTenant {
	return &AzureTenant{}
}

func (a *AzureTenant) Name() string { return "azure_tenant" }

func (a *AzureTenant) Lookup(ctx context.Context, ip net.IP) error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("Azure auth failed: %w", err)
	}

	client, err := armresourcegraph.NewClient(cred, nil)
	if err != nil {
		return fmt.Errorf("Azure Resource Graph client failed: %w", err)
	}

	targetIP := ip.String()

	// Query public IPs across all accessible subscriptions
	query := fmt.Sprintf(`
		Resources
		| where type =~ "microsoft.network/publicipaddresses"
		| where properties.ipAddress == "%s"
		| project
			id,
			name,
			subscriptionId,
			resourceGroup,
			location,
			sku = tostring(sku.name),
			allocationMethod = tostring(properties.publicIPAllocationMethod),
			fqdn = tostring(properties.dnsSettings.fqdn),
			ipConfigId = tostring(properties.ipConfiguration.id)
	`, targetIP)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	resp, err := client.Resources(ctx, armresourcegraph.QueryRequest{
		Query: &query,
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: &resultFormat,
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("Azure Resource Graph query failed: %w", err)
	}

	// Parse results
	data, ok := resp.Data.([]any)
	if !ok || len(data) == 0 {
		a.result = &AzureTenantResult{Found: false}
		return nil
	}

	// Take the first match
	rowBytes, err := json.Marshal(data[0])
	if err != nil {
		return fmt.Errorf("Azure result parsing failed: %w", err)
	}

	var row argPublicIPRow
	if err := json.Unmarshal(rowBytes, &row); err != nil {
		return fmt.Errorf("Azure result unmarshal failed: %w", err)
	}

	result := &AzureTenantResult{
		Found:            true,
		SubscriptionID:   row.SubscriptionID,
		ResourceGroup:    row.ResourceGroup,
		ResourceID:       row.ID,
		PublicIPName:     row.Name,
		Location:         row.Location,
		AllocationMethod: row.AllocationMethod,
		SKU:              row.SKU,
		FQDN:             row.FQDN,
	}

	// Classify attached resource from IP configuration ID
	if row.IPConfigID != "" {
		result.AttachedTo = classifyAzureResource(row.IPConfigID)
		result.AttachedResourceID = row.IPConfigID

		// Try to resolve VM name via a second Resource Graph query
		if strings.Contains(strings.ToLower(row.IPConfigID), "/networkinterfaces/") {
			if vmName := a.resolveNICToVM(ctx, client, row.IPConfigID); vmName != "" {
				result.AttachedTo = "Virtual Machine"
				result.VMName = vmName
			}
		}
	}

	a.result = result
	return nil
}

// resolveNICToVM uses Resource Graph to find the VM attached to a NIC.
func (a *AzureTenant) resolveNICToVM(ctx context.Context, client *armresourcegraph.Client, ipConfigID string) string {
	// Extract the NIC resource ID from the IP configuration ID
	// Format: /subscriptions/.../networkInterfaces/<nic>/ipConfigurations/<config>
	nicID := extractNICIDFromConfigID(ipConfigID)
	if nicID == "" {
		return ""
	}

	query := fmt.Sprintf(`
		Resources
		| where type =~ "microsoft.compute/virtualmachines"
		| mv-expand nic = properties.networkProfile.networkInterfaces
		| where tolower(tostring(nic.id)) == tolower("%s")
		| project name
		| limit 1
	`, nicID)

	resultFormat := armresourcegraph.ResultFormatObjectArray
	resp, err := client.Resources(ctx, armresourcegraph.QueryRequest{
		Query: &query,
		Options: &armresourcegraph.QueryRequestOptions{
			ResultFormat: &resultFormat,
		},
	}, nil)
	if err != nil {
		return ""
	}

	data, ok := resp.Data.([]any)
	if !ok || len(data) == 0 {
		return ""
	}

	rowBytes, _ := json.Marshal(data[0])
	var row struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(rowBytes, &row) == nil {
		return row.Name
	}
	return ""
}

func (a *AzureTenant) Apply(result *Result) {
	result.AzureTenant = a.result
}

// argPublicIPRow maps a single row from the Resource Graph query.
type argPublicIPRow struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	SubscriptionID   string `json:"subscriptionId"`
	ResourceGroup    string `json:"resourceGroup"`
	Location         string `json:"location"`
	SKU              string `json:"sku"`
	AllocationMethod string `json:"allocationMethod"`
	FQDN             string `json:"fqdn"`
	IPConfigID       string `json:"ipConfigId"`
}

// extractNICIDFromConfigID extracts the NIC resource ID from an IP configuration ID.
// Input:  /subscriptions/.../networkInterfaces/<nic>/ipConfigurations/<config>
// Output: /subscriptions/.../networkInterfaces/<nic>
func extractNICIDFromConfigID(configID string) string {
	lower := strings.ToLower(configID)
	idx := strings.Index(lower, "/ipconfigurations/")
	if idx == -1 {
		return ""
	}
	return configID[:idx]
}

// classifyAzureResource determines the resource type from an IP configuration ID.
func classifyAzureResource(configID string) string {
	lower := strings.ToLower(configID)
	switch {
	case strings.Contains(lower, "/networkinterfaces/"):
		return "Network Interface"
	case strings.Contains(lower, "/loadbalancers/"):
		return "Load Balancer"
	case strings.Contains(lower, "/applicationgateways/"):
		return "Application Gateway"
	case strings.Contains(lower, "/bastionhosts/"):
		return "Bastion Host"
	case strings.Contains(lower, "/azurefirewalls/"):
		return "Azure Firewall"
	case strings.Contains(lower, "/natgateways/"):
		return "NAT Gateway"
	default:
		return "Unknown"
	}
}

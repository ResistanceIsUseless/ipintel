package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

// AzureTenant queries the user's Azure subscription for public IP ownership.
type AzureTenant struct {
	subscriptionID string
	result         *AzureTenantResult
}

func NewAzureTenant(subscriptionID string) *AzureTenant {
	return &AzureTenant{subscriptionID: subscriptionID}
}

func (a *AzureTenant) Name() string { return "azure_tenant" }

func (a *AzureTenant) Lookup(ctx context.Context, ip net.IP) error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("Azure auth failed: %w", err)
	}

	client, err := armnetwork.NewPublicIPAddressesClient(a.subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("Azure client creation failed: %w", err)
	}

	targetIP := ip.String()
	pager := client.NewListAllPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("Azure API error listing public IPs: %w", err)
		}

		for _, pip := range page.Value {
			if pip.Properties == nil || pip.Properties.IPAddress == nil {
				continue
			}
			if *pip.Properties.IPAddress != targetIP {
				continue
			}

			// Found a match
			result := &AzureTenantResult{
				Found:          true,
				SubscriptionID: a.subscriptionID,
			}

			if pip.ID != nil {
				result.ResourceID = *pip.ID
				result.ResourceGroup = extractAzureResourceGroup(*pip.ID)
			}
			if pip.Name != nil {
				result.PublicIPName = *pip.Name
			}
			if pip.Location != nil {
				result.Location = *pip.Location
			}
			if pip.Properties.PublicIPAllocationMethod != nil {
				result.AllocationMethod = string(*pip.Properties.PublicIPAllocationMethod)
			}
			if pip.SKU != nil && pip.SKU.Name != nil {
				result.SKU = string(*pip.SKU.Name)
			}
			if pip.Properties.DNSSettings != nil && pip.Properties.DNSSettings.Fqdn != nil {
				result.FQDN = *pip.Properties.DNSSettings.Fqdn
			}

			// Determine attached resource
			if pip.Properties.IPConfiguration != nil && pip.Properties.IPConfiguration.ID != nil {
				configID := *pip.Properties.IPConfiguration.ID
				result.AttachedTo = classifyAzureResource(configID)
				result.AttachedResourceID = configID

				// Try to resolve to the VM if it's a NIC
				if strings.Contains(configID, "/networkInterfaces/") {
					if vmInfo := resolveAzureNICToVM(ctx, cred, a.subscriptionID, configID); vmInfo != "" {
						result.AttachedTo = "Virtual Machine"
						result.VMName = vmInfo
					}
				}
			}

			a.result = result
			return nil
		}
	}

	// IP not found in this subscription
	a.result = &AzureTenantResult{
		Found:          false,
		SubscriptionID: a.subscriptionID,
	}
	return nil
}

func (a *AzureTenant) Apply(result *Result) {
	result.AzureTenant = a.result
}

// extractAzureResourceGroup parses the resource group from an ARM resource ID.
func extractAzureResourceGroup(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
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

// resolveAzureNICToVM gets the VM name from a NIC's IP configuration ID.
func resolveAzureNICToVM(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID, configID string) string {
	// Extract resource group and NIC name from the config ID
	// Format: /subscriptions/.../resourceGroups/<rg>/providers/Microsoft.Network/networkInterfaces/<nic>/ipConfigurations/<config>
	parts := strings.Split(configID, "/")
	var rg, nicName string
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			rg = parts[i+1]
		}
		if strings.EqualFold(p, "networkInterfaces") && i+1 < len(parts) {
			nicName = parts[i+1]
		}
	}
	if rg == "" || nicName == "" {
		return ""
	}

	nicClient, err := armnetwork.NewInterfacesClient(subscriptionID, cred, nil)
	if err != nil {
		return ""
	}

	nic, err := nicClient.Get(ctx, rg, nicName, nil)
	if err != nil {
		return ""
	}

	if nic.Properties != nil && nic.Properties.VirtualMachine != nil && nic.Properties.VirtualMachine.ID != nil {
		vmID := *nic.Properties.VirtualMachine.ID
		// Extract just the VM name from the ID
		vmParts := strings.Split(vmID, "/")
		if len(vmParts) > 0 {
			return vmParts[len(vmParts)-1]
		}
	}

	return ""
}

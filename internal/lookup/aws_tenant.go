package lookup

import (
	"context"
	"fmt"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// AWSTenant queries the user's AWS account for public/elastic IP ownership.
type AWSTenant struct {
	region string
	result *AWSTenantResult
}

func NewAWSTenant(region string) *AWSTenant {
	return &AWSTenant{region: region}
}

func (a *AWSTenant) Name() string { return "aws_tenant" }

func (a *AWSTenant) Lookup(ctx context.Context, ip net.IP) error {
	targetIP := ip.String()

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(a.region))
	if err != nil {
		return fmt.Errorf("AWS auth failed: %w", err)
	}

	client := ec2.NewFromConfig(cfg)

	// Strategy 1: Check Elastic IPs (DescribeAddresses)
	if result := a.checkElasticIPs(ctx, client, targetIP); result != nil {
		a.result = result
		return nil
	}

	// Strategy 2: Check all network interfaces (catches ephemeral IPs, ELBs, NAT GWs)
	if result := a.checkNetworkInterfaces(ctx, client, targetIP); result != nil {
		a.result = result
		return nil
	}

	// Not found in this region
	a.result = &AWSTenantResult{
		Found:  false,
		Region: a.region,
	}
	return nil
}

func (a *AWSTenant) checkElasticIPs(ctx context.Context, client *ec2.Client, targetIP string) *AWSTenantResult {
	resp, err := client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("public-ip"),
				Values: []string{targetIP},
			},
		},
	})
	if err != nil || len(resp.Addresses) == 0 {
		return nil
	}

	addr := resp.Addresses[0]
	result := &AWSTenantResult{
		Found:    true,
		Region:   a.region,
		IPType:   "Elastic IP",
		PublicIP: targetIP,
	}

	if addr.AllocationId != nil {
		result.AllocationID = *addr.AllocationId
	}
	if addr.InstanceId != nil {
		result.InstanceID = *addr.InstanceId
		result.ResourceType = "EC2 Instance"
	}
	if addr.NetworkInterfaceId != nil {
		result.NetworkInterfaceID = *addr.NetworkInterfaceId
	}
	if addr.PrivateIpAddress != nil {
		result.PrivateIP = *addr.PrivateIpAddress
	}
	if addr.AssociationId != nil {
		result.AssociationID = *addr.AssociationId
	}

	return result
}

func (a *AWSTenant) checkNetworkInterfaces(ctx context.Context, client *ec2.Client, targetIP string) *AWSTenantResult {
	resp, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("association.public-ip"),
				Values: []string{targetIP},
			},
		},
	})
	if err != nil || len(resp.NetworkInterfaces) == 0 {
		return nil
	}

	eni := resp.NetworkInterfaces[0]
	result := &AWSTenantResult{
		Found:    true,
		Region:   a.region,
		PublicIP: targetIP,
	}

	if eni.NetworkInterfaceId != nil {
		result.NetworkInterfaceID = *eni.NetworkInterfaceId
	}
	if eni.PrivateIpAddress != nil {
		result.PrivateIP = *eni.PrivateIpAddress
	}
	if eni.Description != nil {
		result.Description = *eni.Description
	}
	if eni.OwnerId != nil {
		result.AccountID = *eni.OwnerId
	}
	if eni.AvailabilityZone != nil {
		result.AvailabilityZone = *eni.AvailabilityZone
	}
	if eni.VpcId != nil {
		result.VPCID = *eni.VpcId
	}
	if eni.SubnetId != nil {
		result.SubnetID = *eni.SubnetId
	}

	// Classify resource type from interface type
	result.ResourceType = classifyAWSInterface(eni.InterfaceType)
	result.IPType = "Ephemeral"

	// If it's an EC2 instance, get the instance ID
	if eni.Attachment != nil && eni.Attachment.InstanceId != nil {
		result.InstanceID = *eni.Attachment.InstanceId
		result.ResourceType = "EC2 Instance"
	}

	return result
}

func classifyAWSInterface(ifaceType ec2types.NetworkInterfaceType) string {
	switch ifaceType {
	case ec2types.NetworkInterfaceTypeInterface:
		return "EC2 Instance"
	case ec2types.NetworkInterfaceTypeNatGateway:
		return "NAT Gateway"
	case "network_load_balancer":
		return "Network Load Balancer"
	case "gateway_load_balancer":
		return "Gateway Load Balancer"
	case "gateway_load_balancer_endpoint":
		return "Gateway LB Endpoint"
	case ec2types.NetworkInterfaceTypeLambda:
		return "Lambda"
	case ec2types.NetworkInterfaceTypeEfa:
		return "Elastic Fabric Adapter"
	case "api_gateway_managed":
		return "API Gateway"
	default:
		if ifaceType != "" {
			return string(ifaceType)
		}
		return "Unknown"
	}
}

func (a *AWSTenant) Apply(result *Result) {
	result.AWSTenant = a.result
}

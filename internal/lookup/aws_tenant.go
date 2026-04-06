package lookup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
)

// Standard AWS regions to search.
var defaultAWSRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
	"sa-east-1", "ca-central-1",
	"me-south-1", "af-south-1",
}

// AWSTenant queries AWS accounts for public/elastic IP ownership.
// Supports two modes:
//  1. SSO org mode: discovers all accounts via SSO, assumes a role in each
//  2. Profile mode: uses explicit AWS CLI profiles (legacy/fallback)
type AWSTenant struct {
	// SSO org mode
	ssoRegion string
	roleName  string

	// Profile fallback mode
	profiles []string
	regions  []string

	result *AWSTenantResult
}

// AWSTenantConfig holds configuration for the AWS tenant provider.
type AWSTenantConfig struct {
	SSORoleName string   // SSO role to assume in each account (e.g., "ReadOnlyAccess")
	SSORegion   string   // SSO portal region (e.g., "us-east-1")
	Profiles    []string // fallback: explicit AWS CLI profiles
	Regions     []string // regions to search (empty = all default regions)
}

func NewAWSTenant(cfg AWSTenantConfig) *AWSTenant {
	if len(cfg.Regions) == 0 {
		cfg.Regions = defaultAWSRegions
	}
	if cfg.SSORegion == "" {
		cfg.SSORegion = "us-east-1"
	}
	return &AWSTenant{
		ssoRegion: cfg.SSORegion,
		roleName:  cfg.SSORoleName,
		profiles:  cfg.Profiles,
		regions:   cfg.Regions,
	}
}

func (a *AWSTenant) Name() string { return "aws_tenant" }

func (a *AWSTenant) Lookup(ctx context.Context, ip net.IP) error {
	targetIP := ip.String()

	// Try SSO org mode first if a role name is configured
	if a.roleName != "" {
		result, err := a.lookupViaSSO(ctx, targetIP)
		if err == nil && result != nil {
			a.result = result
			return nil
		}
		// If SSO failed but we have profile fallback, continue
		if len(a.profiles) == 0 {
			if err != nil {
				return fmt.Errorf("AWS SSO lookup failed: %w", err)
			}
			// SSO worked but IP not found
			a.result = &AWSTenantResult{Found: false}
			return nil
		}
		// Fall through to profile mode
	}

	// Profile mode (fallback or explicit)
	if len(a.profiles) > 0 {
		result, err := a.lookupViaProfiles(ctx, targetIP)
		if err != nil {
			return err
		}
		a.result = result
		return nil
	}

	// No SSO role and no profiles — try default credential chain in all regions
	result, err := a.lookupViaProfiles(ctx, targetIP)
	if err != nil {
		return err
	}
	a.result = result
	return nil
}

// lookupViaSSO discovers all org accounts via SSO and searches each.
func (a *AWSTenant) lookupViaSSO(ctx context.Context, targetIP string) (*AWSTenantResult, error) {
	token, err := readSSOAccessToken()
	if err != nil {
		return nil, fmt.Errorf("reading SSO token: %w (run 'aws sso login' first)", err)
	}

	// Create SSO client
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(a.ssoRegion))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	ssoClient := sso.NewFromConfig(cfg)

	// Discover all accounts
	accounts, err := a.listAllAccounts(ctx, ssoClient, token)
	if err != nil {
		return nil, fmt.Errorf("listing SSO accounts: %w", err)
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("no AWS accounts found via SSO")
	}

	// Phase 1: Get credentials for all accounts concurrently
	type accountCreds struct {
		account ssotypes.AccountInfo
		creds   *ssotypes.RoleCredentials
	}

	credsCh := make(chan accountCreds, len(accounts))
	var credsWg sync.WaitGroup
	credsSem := make(chan struct{}, 10)

	for _, acct := range accounts {
		credsWg.Add(1)
		go func(account ssotypes.AccountInfo) {
			defer credsWg.Done()
			credsSem <- struct{}{}
			defer func() { <-credsSem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			roleCreds, err := ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
				AccessToken: &token,
				AccountId:   account.AccountId,
				RoleName:    &a.roleName,
			})
			if err != nil || roleCreds.RoleCredentials == nil || roleCreds.RoleCredentials.AccessKeyId == nil {
				return // skip accounts where role isn't available
			}

			credsCh <- accountCreds{account: account, creds: roleCreds.RoleCredentials}
		}(acct)
	}

	credsWg.Wait()
	close(credsCh)

	// Collect all valid credentials
	var validAccounts []accountCreds
	for ac := range credsCh {
		validAccounts = append(validAccounts, ac)
	}

	if len(validAccounts) == 0 {
		return nil, fmt.Errorf("no accounts accessible with role %q", a.roleName)
	}

	// Phase 2: Search all account+region combinations concurrently
	type searchResult struct {
		result *AWSTenantResult
	}

	resultCh := make(chan searchResult, 1)
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 15) // higher concurrency now that creds are cached

	for _, ac := range validAccounts {
		for _, region := range a.regions {
			wg.Add(1)
			go func(ac accountCreds, reg string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				select {
				case <-searchCtx.Done():
					return
				default:
				}

				rc := ac.creds
				ec2Cfg, err := awsconfig.LoadDefaultConfig(searchCtx,
					awsconfig.WithRegion(reg),
					awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
						aws.ToString(rc.AccessKeyId),
						aws.ToString(rc.SecretAccessKey),
						aws.ToString(rc.SessionToken),
					)),
				)
				if err != nil {
					return
				}

				ec2Client := ec2.NewFromConfig(ec2Cfg)
				accountName := aws.ToString(ac.account.AccountName)
				accountID := aws.ToString(ac.account.AccountId)

				// Check Elastic IPs
				if r := checkElasticIPs(searchCtx, ec2Client, accountID, accountName, reg, targetIP); r != nil {
					select {
					case resultCh <- searchResult{result: r}:
						cancel()
					default:
					}
					return
				}

				// Check network interfaces
				if r := checkNetworkInterfaces(searchCtx, ec2Client, accountID, accountName, reg, targetIP); r != nil {
					select {
					case resultCh <- searchResult{result: r}:
						cancel()
					default:
					}
					return
				}
			}(ac, region)
		}
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if sr, ok := <-resultCh; ok && sr.result != nil {
		return sr.result, nil
	}

	return &AWSTenantResult{Found: false}, nil
}

// lookupViaProfiles searches using explicit AWS CLI profiles.
func (a *AWSTenant) lookupViaProfiles(ctx context.Context, targetIP string) (*AWSTenantResult, error) {
	profiles := a.profiles
	if len(profiles) == 0 {
		profiles = []string{""} // default credential chain
	}

	type searchResult struct {
		result *AWSTenantResult
	}

	resultCh := make(chan searchResult, 1)
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, profile := range profiles {
		for _, region := range a.regions {
			wg.Add(1)
			go func(prof, reg string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				select {
				case <-searchCtx.Done():
					return
				default:
				}

				opts := []func(*awsconfig.LoadOptions) error{
					awsconfig.WithRegion(reg),
				}
				if prof != "" {
					opts = append(opts, awsconfig.WithSharedConfigProfile(prof))
				}

				cfg, err := awsconfig.LoadDefaultConfig(searchCtx, opts...)
				if err != nil {
					return
				}

				client := ec2.NewFromConfig(cfg)

				if r := checkElasticIPs(searchCtx, client, "", prof, reg, targetIP); r != nil {
					select {
					case resultCh <- searchResult{result: r}:
						cancel()
					default:
					}
					return
				}

				if r := checkNetworkInterfaces(searchCtx, client, "", prof, reg, targetIP); r != nil {
					select {
					case resultCh <- searchResult{result: r}:
						cancel()
					default:
					}
					return
				}
			}(profile, region)
		}
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if sr, ok := <-resultCh; ok && sr.result != nil {
		return sr.result, nil
	}

	return &AWSTenantResult{Found: false}, nil
}

// listAllAccounts pages through all SSO accounts.
func (a *AWSTenant) listAllAccounts(ctx context.Context, client *sso.Client, token string) ([]ssotypes.AccountInfo, error) {
	var accounts []ssotypes.AccountInfo
	var nextToken *string

	for {
		resp, err := client.ListAccounts(ctx, &sso.ListAccountsInput{
			AccessToken: &token,
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, resp.AccountList...)
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return accounts, nil
}

func (a *AWSTenant) Apply(result *Result) {
	result.AWSTenant = a.result
}

// --- EC2 search helpers ---

func checkElasticIPs(ctx context.Context, client *ec2.Client, accountID, accountName, region, targetIP string) *AWSTenantResult {
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
		Found:       true,
		Region:      region,
		AccountID:   accountID,
		AccountName: accountName,
		IPType:      "Elastic IP",
		PublicIP:    targetIP,
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
	if addr.NetworkInterfaceOwnerId != nil && accountID == "" {
		result.AccountID = *addr.NetworkInterfaceOwnerId
	}

	// Extract Name tag if present
	for _, tag := range addr.Tags {
		if aws.ToString(tag.Key) == "Name" {
			result.ResourceName = aws.ToString(tag.Value)
			break
		}
	}

	return result
}

func checkNetworkInterfaces(ctx context.Context, client *ec2.Client, accountID, accountName, region, targetIP string) *AWSTenantResult {
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
		Found:       true,
		Region:      region,
		AccountID:   accountID,
		AccountName: accountName,
		PublicIP:    targetIP,
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
	if eni.OwnerId != nil && accountID == "" {
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

	result.ResourceType = classifyAWSInterface(eni.InterfaceType)
	result.IPType = "Ephemeral"

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

// --- SSO token reader ---

// ssoTokenCache represents the JSON structure of an SSO token cache file.
type ssoTokenCache struct {
	AccessToken  string `json:"accessToken"`
	ExpiresAt    string `json:"expiresAt"`
	StartURL     string `json:"startUrl"`
	Region       string `json:"region"`
	RefreshToken string `json:"refreshToken"`
}

// readSSOAccessToken reads the most recent valid SSO access token from ~/.aws/sso/cache/.
func readSSOAccessToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find home directory: %w", err)
	}

	cacheDir := filepath.Join(home, ".aws", "sso", "cache")
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", fmt.Errorf("cannot read SSO cache directory: %w", err)
	}

	var bestToken string
	var bestExpiry time.Time

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(cacheDir, entry.Name()))
		if err != nil {
			continue
		}

		var cache ssoTokenCache
		if err := json.Unmarshal(data, &cache); err != nil {
			continue
		}

		// Must have an access token and a start URL (distinguishes token files from client registration files)
		if cache.AccessToken == "" || cache.StartURL == "" {
			continue
		}

		// Parse expiry and check validity
		expiry, err := time.Parse(time.RFC3339, cache.ExpiresAt)
		if err != nil {
			// Try alternate format
			expiry, err = time.Parse("2006-01-02T15:04:05Z", cache.ExpiresAt)
			if err != nil {
				continue
			}
		}

		if time.Now().After(expiry) {
			continue // expired
		}

		// Pick the most recently expiring (freshest) token
		if expiry.After(bestExpiry) {
			bestExpiry = expiry
			bestToken = cache.AccessToken
		}
	}

	if bestToken == "" {
		return "", fmt.Errorf("no valid SSO access token found (run 'aws sso login')")
	}

	return bestToken, nil
}

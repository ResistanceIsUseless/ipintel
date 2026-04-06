package lookup

import (
	"context"
	"net"
)

// ReverseDNS performs PTR record lookups.
type ReverseDNS struct {
	hostnames []string
}

func NewReverseDNS() *ReverseDNS {
	return &ReverseDNS{}
}

func (r *ReverseDNS) Name() string { return "reverse_dns" }

func (r *ReverseDNS) Lookup(ctx context.Context, ip net.IP) error {
	resolver := net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil
		}
		return err
	}
	r.hostnames = names
	return nil
}

func (r *ReverseDNS) Apply(result *Result) {
	result.ReverseDNS = r.hostnames
}

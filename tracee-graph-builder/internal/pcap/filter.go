package pcap

import (
	"fmt"
	"net/netip"
)

var defaultExcludeCIDRs = []string{
	"172.16.17.0/24",
	"10.68.0.0/14",
	"34.118.224.0/20",
	"127.0.0.0/8",
	"::1/128",
	"169.254.0.0/16",
	"fe80::/10",
	"224.0.0.0/4",
	"ff00::/8",
}

// DefaultExcludeCIDRs returns built-in internal and non-routable prefixes.
func DefaultExcludeCIDRs() ([]netip.Prefix, error) {
	return ParseCIDRs(defaultExcludeCIDRs)
}

// ParseCIDRs parses CIDR strings into prefixes.
func ParseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", cidr, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

// IsInternalIP reports whether ip falls within any excluded prefix.
func IsInternalIP(ip netip.Addr, exclude []netip.Prefix) bool {
	if !ip.IsValid() {
		return true
	}
	for _, prefix := range exclude {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

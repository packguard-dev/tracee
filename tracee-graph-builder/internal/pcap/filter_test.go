package pcap

import (
	"net/netip"
	"testing"
)

func TestIsInternalIP(t *testing.T) {
	t.Parallel()

	exclude, err := DefaultExcludeCIDRs()
	if err != nil {
		t.Fatalf("DefaultExcludeCIDRs: %v", err)
	}

	cases := []struct {
		ip       string
		internal bool
	}{
		{ip: "172.16.17.10", internal: true},
		{ip: "10.68.0.5", internal: true},
		{ip: "34.118.224.10", internal: true},
		{ip: "127.0.0.1", internal: true},
		{ip: "185.199.108.133", internal: false},
	}

	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.ip)
		got := IsInternalIP(addr, exclude)
		if got != tc.internal {
			t.Fatalf("IsInternalIP(%s) = %v, want %v", tc.ip, got, tc.internal)
		}
	}
}

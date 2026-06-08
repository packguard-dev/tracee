package pcap

import "testing"

func TestNormalizeDNSName(t *testing.T) {
	t.Parallel()

	got := normalizeDNSName("mysvc.default.svc.cluster.local")
	want := "mysvc.default"
	if got != want {
		t.Fatalf("normalizeDNSName() = %q, want %q", got, want)
	}
}

package pcap

import (
	"os"
	"testing"
)

func TestParseFileExtractsExternalFlows(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	if err != nil {
		t.Fatalf("BuildTestFixture: %v", err)
	}
	path := writeTempPcap(t, data)

	exclude, err := DefaultExcludeCIDRs()
	if err != nil {
		t.Fatalf("DefaultExcludeCIDRs: %v", err)
	}

	flows, err := ParseFile(path, exclude)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(flows) < 2 {
		t.Fatalf("expected at least 2 flows, got %d", len(flows))
	}

	foundTCP := false
	foundDNS := false
	for _, flow := range flows {
		if flow.IP == "185.199.108.133" && flow.Protocol == "TCP" && flow.Port == 443 {
			foundTCP = true
		}
		if flow.Domain == "raw.githubusercontent.com" && flow.Protocol == "DNS" {
			foundDNS = true
		}
	}
	if !foundTCP {
		t.Fatal("missing external TCP flow")
	}
	if !foundDNS {
		t.Fatal("missing external DNS flow")
	}
}

func writeTempPcap(t *testing.T, data []byte) string {
	t.Helper()
	path := t.TempDir() + "/test.pcapng"
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write temp pcap: %v", err)
	}
	return path
}

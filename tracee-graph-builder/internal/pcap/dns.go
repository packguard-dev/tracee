package pcap

import (
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/netutil"
)

func normalizeDNSName(name string) string {
	return netutil.NormalizeDomain(strings.TrimSpace(name))
}

func dnsNamesFromLayer(dns *layers.DNS) []string {
	if dns == nil {
		return nil
	}
	out := make([]string, 0, len(dns.Questions))
	for _, q := range dns.Questions {
		name := normalizeDNSName(string(q.Name))
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

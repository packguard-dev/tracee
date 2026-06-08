package build

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/pcap"
)

// EnrichFromPcap attaches external network indicators from a PCAP file to IOCs.
func EnrichFromPcap(out model.Output, pcapPath string, window time.Duration, excludeCIDRs []netip.Prefix) (model.Output, error) {
	if pcapPath == "" {
		return out, nil
	}
	if len(out.IOCs) == 0 {
		out.Meta.PcapSource = pcapPath
		return out, nil
	}

	exclude := excludeCIDRs
	defaults, err := pcap.DefaultExcludeCIDRs()
	if err != nil {
		return out, fmt.Errorf("default exclude cidrs: %w", err)
	}
	exclude = MergeExcludeCIDRs(defaults, exclude)

	idx, err := pcap.OpenIndex(pcapPath, exclude)
	if err != nil {
		return out, err
	}

	return pcap.EnrichIOCs(out, idx, pcap.EnrichOptions{
		Source:  pcapPath,
		Window:  window,
		Exclude: exclude,
	}), nil
}

// MergeExcludeCIDRs appends user-provided CIDRs to defaults.
func MergeExcludeCIDRs(defaults, extra []netip.Prefix) []netip.Prefix {
	if len(extra) == 0 {
		return defaults
	}
	merged := make([]netip.Prefix, 0, len(defaults)+len(extra))
	merged = append(merged, defaults...)
	merged = append(merged, extra...)
	return merged
}

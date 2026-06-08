package pcap

import (
	"fmt"
	"sort"
	"time"

	"net/netip"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

// EnrichOptions configures IOC PCAP enrichment.
type EnrichOptions struct {
	Source    string
	Window    time.Duration
	Exclude   []netip.Prefix
}

// EnrichIOCs attaches external PCAP indicators to each IOC record.
func EnrichIOCs(out model.Output, idx *Index, opts EnrichOptions) model.Output {
	if idx == nil || len(out.IOCs) == 0 {
		return out
	}

	windowSec := int(opts.Window.Seconds())
	enriched := make([]model.IOCRecord, len(out.IOCs))
	for i, ioc := range out.IOCs {
		enriched[i] = enrichOneIOC(ioc, idx, opts.Source, windowSec, opts.Window)
	}
	out.IOCs = enriched
	out.Meta.PcapSource = opts.Source
	return out
}

func enrichOneIOC(ioc model.IOCRecord, idx *Index, source string, windowSec int, window time.Duration) model.IOCRecord {
	flows := idx.FlowsInWindow(ioc.Timestamp, window)
	if len(flows) == 0 {
		return ioc
	}

	hints := hintsFromIOC(ioc)
	matchMode := model.PcapMatchModeWindow
	selected := flows
	if hints.hasHints() {
		matchMode = model.PcapMatchModeHints
		filtered := make([]FlowRecord, 0, len(flows))
		for _, flow := range flows {
			if hints.matchesFlow(flow) {
				filtered = append(filtered, flow)
			}
		}
		selected = filtered
	}

	indicators := dedupeIndicators(selected)
	if len(indicators) == 0 {
		return ioc
	}

	ioc.Pcap = &model.PcapEnrichment{
		Source:     source,
		WindowSec:  windowSec,
		MatchMode:  matchMode,
		Indicators: indicators,
	}
	return ioc
}

func dedupeIndicators(flows []FlowRecord) []model.ExternalIndicator {
	type key struct {
		ip       string
		port     int32
		protocol string
		domain   string
	}
	seen := make(map[key]struct{}, len(flows))
	out := make([]model.ExternalIndicator, 0, len(flows))

	for _, flow := range flows {
		k := key{
			ip:       flow.IP,
			port:     flow.Port,
			protocol: flow.Protocol,
			domain:   flow.Domain,
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, model.ExternalIndicator{
			IP:       flow.IP,
			Port:     flow.Port,
			Protocol: flow.Protocol,
			Domain:   flow.Domain,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}

// OpenIndex parses a PCAP file and returns an index for enrichment.
func OpenIndex(path string, exclude []netip.Prefix) (*Index, error) {
	idx, err := NewIndex(path, exclude)
	if err != nil {
		return nil, fmt.Errorf("parse pcap %q: %w", path, err)
	}
	return idx, nil
}

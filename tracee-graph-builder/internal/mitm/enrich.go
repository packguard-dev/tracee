package mitm

import (
	"sort"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

// EnrichOptions configures IOC MITM enrichment.
type EnrichOptions struct {
	Source string
	Window time.Duration
}

// EnrichIOCs attaches MITM proxy requests to each IOC record.
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
	out.Meta.MitmSource = opts.Source
	return out
}

func enrichOneIOC(ioc model.IOCRecord, idx *Index, source string, windowSec int, window time.Duration) model.IOCRecord {
	records := idx.RecordsInWindow(ioc.Timestamp, window)
	if len(records) == 0 {
		return ioc
	}

	hints := hintsFromIOC(ioc)
	matchMode := model.PcapMatchModeWindow
	selected := records
	if hints.hasHints() {
		matchMode = model.PcapMatchModeHints
		filtered := make([]Record, 0, len(records))
		for _, record := range records {
			if hints.matchesRecord(record) {
				filtered = append(filtered, record)
			}
		}
		selected = filtered
	}

	requests := recordsToRequests(selected)
	if len(requests) == 0 {
		return ioc
	}

	ioc.Mitm = &model.MitmEnrichment{
		Source:    source,
		WindowSec: windowSec,
		MatchMode: matchMode,
		Requests:  requests,
	}
	return ioc
}

func recordsToRequests(records []Record) []model.MitmRequest {
	out := make([]model.MitmRequest, 0, len(records))
	for _, record := range records {
		out = append(out, model.MitmRequest{
			Timestamp:     record.Timestamp,
			Host:          record.Host,
			Port:          record.Port,
			Scheme:        record.Scheme,
			URL:           record.URL,
			Method:        record.Method,
			SNI:           record.SNI,
			ResponseBytes: record.ResponseBytes,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].Timestamp.Before(out[j].Timestamp)
		}
		return out[i].URL < out[j].URL
	})
	return out
}

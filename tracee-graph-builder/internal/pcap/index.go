package pcap

import (
	"sort"
	"time"

	"net/netip"
)

// Index holds parsed flow records sorted by timestamp.
type Index struct {
	Flows []FlowRecord
}

// NewIndex parses a pcap file and builds a time-sorted index.
func NewIndex(path string, exclude []netip.Prefix) (*Index, error) {
	flows, err := ParseFile(path, exclude)
	if err != nil {
		return nil, err
	}
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].Timestamp.Before(flows[j].Timestamp)
	})
	return &Index{Flows: flows}, nil
}

// FlowsInWindow returns flows whose timestamps fall within center +/- window.
func (idx *Index) FlowsInWindow(center time.Time, window time.Duration) []FlowRecord {
	if idx == nil || len(idx.Flows) == 0 || center.IsZero() {
		return nil
	}
	start := center.Add(-window)
	end := center.Add(window)

	left := sort.Search(len(idx.Flows), func(i int) bool {
		return !idx.Flows[i].Timestamp.Before(start)
	})
	right := sort.Search(len(idx.Flows), func(i int) bool {
		return idx.Flows[i].Timestamp.After(end)
	})
	if left >= right {
		return nil
	}
	out := make([]FlowRecord, right-left)
	copy(out, idx.Flows[left:right])
	return out
}

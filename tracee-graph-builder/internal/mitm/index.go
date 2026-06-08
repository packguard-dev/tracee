package mitm

import (
	"fmt"
	"sort"
	"time"
)

// Index holds parsed MITM records sorted by timestamp.
type Index struct {
	Records []Record
}

// NewIndex parses an MITM JSONL file and builds a time-sorted index.
func NewIndex(path string) (*Index, error) {
	records, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})
	return &Index{Records: records}, nil
}

// RecordsInWindow returns records whose timestamps fall within center +/- window.
func (idx *Index) RecordsInWindow(center time.Time, window time.Duration) []Record {
	if idx == nil || len(idx.Records) == 0 || center.IsZero() {
		return nil
	}
	start := center.Add(-window)
	end := center.Add(window)

	left := sort.Search(len(idx.Records), func(i int) bool {
		return !idx.Records[i].Timestamp.Before(start)
	})
	right := sort.Search(len(idx.Records), func(i int) bool {
		return idx.Records[i].Timestamp.After(end)
	})
	if left >= right {
		return nil
	}
	out := make([]Record, right-left)
	copy(out, idx.Records[left:right])
	return out
}

// OpenIndex parses an MITM JSONL file and returns an index for enrichment.
func OpenIndex(path string) (*Index, error) {
	idx, err := NewIndex(path)
	if err != nil {
		return nil, fmt.Errorf("parse mitm %q: %w", path, err)
	}
	return idx, nil
}

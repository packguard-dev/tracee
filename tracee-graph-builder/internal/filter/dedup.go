package filter

import (
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

type dedupKey struct {
	eventName  string
	inode      uint64
	ctime      uint64
	processKey string
}

type networkDedupKey struct {
	eventName  string
	processKey string
	dstDNS     string
	dstPort    int32
}

var dedupEventNames = map[string]struct{}{
	"security_file_open":    {},
	"security_inode_rename": {},
	"file_modification":     {},
	"security_inode_unlink": {},
}

// DedupFileEvents drops duplicate file-activity events for a given
// (inode,ctime,processKey) key within the provided time window.
// Events that do not have inode+ctime+processKey+timestamp are preserved. Order is preserved.
func DedupFileEvents(events []model.NormalizedEvent, window time.Duration) []model.NormalizedEvent {
	if len(events) == 0 || window <= 0 {
		return events
	}

	lastSeen := make(map[dedupKey]time.Time)
	out := make([]model.NormalizedEvent, 0, len(events))

	for _, ev := range events {
		if _, ok := dedupEventNames[ev.EventName]; !ok {
			out = append(out, ev)
			continue
		}

		if ev.ProcessKey == "" || ev.Timestamp.IsZero() {
			out = append(out, ev)
			continue
		}

		inode, okInode := input.Uint64FromField(ev.Fields, "inode")
		ctime, okCtime := input.Uint64FromField(ev.Fields, "ctime")
		if !okInode || !okCtime || inode == 0 || ctime == 0 {
			out = append(out, ev)
			continue
		}

		key := dedupKey{
			eventName:  ev.EventName,
			inode:      inode,
			ctime:      ctime,
			processKey: ev.ProcessKey,
		}
		if last, ok := lastSeen[key]; ok {
			if !ev.Timestamp.After(last.Add(window)) {
				continue
			}
		}

		lastSeen[key] = ev.Timestamp
		out = append(out, ev)
	}

	return out
}

var networkDedupEventNames = map[string]struct{}{
	"net_tcp_connect": {},
}

// DedupNetworkEvents drops duplicate net_tcp_connect events for a given
// (processKey, dst_dns, dst_port) key within the provided time window.
func DedupNetworkEvents(events []model.NormalizedEvent, window time.Duration) []model.NormalizedEvent {
	if len(events) == 0 || window <= 0 {
		return events
	}

	lastSeen := make(map[networkDedupKey]time.Time)
	out := make([]model.NormalizedEvent, 0, len(events))

	for _, ev := range events {
		if _, ok := networkDedupEventNames[ev.EventName]; !ok {
			out = append(out, ev)
			continue
		}

		if ev.ProcessKey == "" || ev.Timestamp.IsZero() {
			out = append(out, ev)
			continue
		}

		dstPort, okPort := input.Int32FromField(ev.Fields, "dst_port")
		if !okPort {
			out = append(out, ev)
			continue
		}

		key := networkDedupKey{
			eventName:  ev.EventName,
			processKey: ev.ProcessKey,
			dstDNS:     canonicalizeDNSNames(input.StringSliceFromField(ev.Fields, "dst_dns")),
			dstPort:    dstPort,
		}
		if last, ok := lastSeen[key]; ok {
			if !ev.Timestamp.After(last.Add(window)) {
				continue
			}
		}

		lastSeen[key] = ev.Timestamp
		out = append(out, ev)
	}

	return out
}

func canonicalizeDNSNames(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

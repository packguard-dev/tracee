package pcap

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/netutil"
)

type iocHints struct {
	domains   []string
	addresses []string
	endpoints []string
}

func hintsFromIOC(ioc model.IOCRecord) iocHints {
	domains := make([]string, 0)
	addresses := make([]string, 0)
	endpoints := make([]string, 0)

	addDomain := func(name string) {
		name = netutil.NormalizeDomain(strings.TrimSpace(name))
		if name != "" {
			domains = append(domains, name)
		}
	}
	addAddress := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			addresses = append(addresses, addr)
		}
	}
	addEndpoint := func(dst string, port int32) {
		dst = strings.TrimSpace(dst)
		if dst == "" {
			return
		}
		endpoints = append(endpoints, fmt.Sprintf("%s:%d", dst, port))
	}

	for _, name := range []string{"domain", "query", "base_domain"} {
		addDomain(input.StringFromField(ioc.Fields, name))
	}
	if dst := input.StringFromField(ioc.Fields, "dst"); dst != "" {
		addAddress(dst)
		if port, ok := input.Int32FromField(ioc.Fields, "dst_port"); ok {
			addEndpoint(dst, port)
		}
	}

	if ioc.DetectedFrom != nil {
		for _, name := range []string{"domain", "query"} {
			addDomain(input.StringFromField(ioc.DetectedFrom.Data, name))
		}
		if dst := packetMetadataString(ioc.DetectedFrom.Data, "dst_ip"); dst != "" {
			addAddress(dst)
			if port, ok := packetMetadataInt32(ioc.DetectedFrom.Data, "dst_port"); ok {
				addEndpoint(dst, port)
			}
		}
		for _, query := range dnsQuestionsFromData(ioc.DetectedFrom.Data) {
			addDomain(query)
		}
	}

	return iocHints{
		domains:   uniqueStrings(domains),
		addresses: uniqueStrings(addresses),
		endpoints: uniqueStrings(endpoints),
	}
}

func (h iocHints) hasHints() bool {
	return len(h.domains) > 0 || len(h.addresses) > 0 || len(h.endpoints) > 0
}

func (h iocHints) matchesFlow(flow FlowRecord) bool {
	if flow.Domain != "" {
		for _, hint := range h.domains {
			if netutil.DomainMatches(flow.Domain, hint) {
				return true
			}
		}
	}
	for _, addr := range h.addresses {
		if flow.IP == addr {
			if len(h.endpoints) == 0 {
				return true
			}
			for _, endpoint := range h.endpoints {
				if endpoint == fmt.Sprintf("%s:%d", flow.IP, flow.Port) {
					return true
				}
			}
			return true
		}
	}
	for _, endpoint := range h.endpoints {
		if endpoint == fmt.Sprintf("%s:%d", flow.IP, flow.Port) {
			return true
		}
	}
	return false
}

func packetMetadataString(data map[string]any, field string) string {
	if data == nil {
		return ""
	}
	meta, ok := data["packet_metadata"].(map[string]any)
	if !ok {
		if meta, ok = data["metadata"].(map[string]any); !ok {
			return ""
		}
	}
	return input.StringFromField(meta, field)
}

func packetMetadataInt32(data map[string]any, field string) (int32, bool) {
	if data == nil {
		return 0, false
	}
	meta, ok := data["packet_metadata"].(map[string]any)
	if !ok {
		if meta, ok = data["metadata"].(map[string]any); !ok {
			return 0, false
		}
	}
	return input.Int32FromField(meta, field)
}

func dnsQuestionsFromData(data map[string]any) []string {
	if data == nil {
		return nil
	}
	questionsRaw, ok := data["dns_questions"]
	if !ok {
		return nil
	}
	switch typed := questionsRaw.(type) {
	case map[string]any:
		if questions, ok := typed["questions"].([]any); ok {
			return dnsQuestionNames(questions)
		}
	case []any:
		return dnsQuestionNames(typed)
	}
	return nil
}

func dnsQuestionNames(items []any) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch typed := item.(type) {
		case map[string]any:
			if query := input.StringFromField(typed, "query", "name"); query != "" {
				out = append(out, query)
			}
		case string:
			if typed != "" {
				out = append(out, typed)
			}
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

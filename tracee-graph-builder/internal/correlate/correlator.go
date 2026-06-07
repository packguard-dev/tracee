package correlate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/graph"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/parallel"
)

type Correlator struct {
	window time.Duration
}

func New(window time.Duration) *Correlator {
	return &Correlator{window: window}
}

func (c *Correlator) Apply(builder *graph.Builder) {
	c.ApplyParallel(builder, parallel.WorkerCount(0))
}

// ApplyParallel correlates IOCs in parallel and merges patches sequentially.
func (c *Correlator) ApplyParallel(builder *graph.Builder, workers int) {
	nodes := builder.Nodes()
	files := builder.FileByID()
	networks := builder.NetworkByID()
	iocs := builder.IOCs()
	if len(iocs) == 0 {
		return
	}

	byProcess := buildFileIndex(files)
	byProcessNetwork := buildNetworkIndex(networks)
	fileByPath := builder.FileByPath()
	networkByDomain := builder.NetworkByDomain()
	networkByAddress := builder.NetworkByAddress()
	networkByEndpoint := builder.NetworkByEndpoint()
	renameRecords := append([]model.FileRecord(nil), builder.Files().Rename...)

	workers = parallel.WorkerCount(workers)
	patches := make([]correlationPatch, len(iocs))
	_ = parallel.Run(context.Background(), workers, len(iocs), func(i int) error {
		patches[i] = correlateOne(
			iocs[i],
			nodes,
			fileByPath,
			networkByDomain,
			networkByAddress,
			networkByEndpoint,
			renameRecords,
			byProcess,
			byProcessNetwork,
			c.window,
		)
		return nil
	})

	for i, patch := range patches {
		iocs[i] = patch.IOC

		for _, fileID := range patch.IOC.RelatedFileIDs {
			record := files[fileID]
			record.IOCIDs = appendUnique(record.IOCIDs, patch.IOC.ID)
			files[fileID] = record
			builder.UpdateFileRecord(record)
		}
		for _, networkID := range patch.IOC.RelatedNetworkIDs {
			record := networks[networkID]
			record.IOCIDs = appendUnique(record.IOCIDs, patch.IOC.ID)
			networks[networkID] = record
			builder.UpdateNetworkRecord(record)
		}
		for _, processKey := range patch.IOC.RelatedProcessKeys {
			node := nodes[processKey]
			node.IOCIDs = appendUnique(node.IOCIDs, patch.IOC.ID)
			nodes[processKey] = node
		}
	}

	builder.SetIOCs(iocs)
}

type correlationPatch struct {
	IOC model.IOCRecord
}

func correlateOne(
	ioc model.IOCRecord,
	nodes map[string]model.ProcessNode,
	fileByPath map[string][]string,
	networkByDomain map[string][]string,
	networkByAddress map[string][]string,
	networkByEndpoint map[string][]string,
	renameRecords []model.FileRecord,
	byProcess map[string][]model.FileRecord,
	byProcessNetwork map[string][]model.NetworkRecord,
	window time.Duration,
) correlationPatch {
	relatedProcesses := make(map[string]struct{})
	relatedFiles := make(map[string]struct{})
	relatedNetworks := make(map[string]struct{})
	relations := make([]model.IOCRelation, 0)

	if ioc.ProcessKey != "" {
		relatedProcesses[ioc.ProcessKey] = struct{}{}
		relations = append(relations, model.IOCRelation{
			Kind:   "process",
			Target: ioc.ProcessKey,
			Reason: "direct_process",
		})
	}

	for _, key := range ancestorChain(nodes, ioc.ProcessKey) {
		relatedProcesses[key] = struct{}{}
		relations = append(relations, model.IOCRelation{
			Kind:   "process",
			Target: key,
			Reason: "ancestor",
		})
	}

	for _, key := range descendantKeys(nodes, ioc.ProcessKey, ioc.Timestamp, window) {
		relatedProcesses[key] = struct{}{}
		relations = append(relations, model.IOCRelation{
			Kind:   "process",
			Target: key,
			Reason: "descendant_window",
		})
	}

	for _, path := range filePathsFromIOC(ioc) {
		for _, fileID := range fileByPath[path] {
			relatedFiles[fileID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "file",
				Target: fileID,
				Reason: "direct_file_field",
			})
		}
		for _, fileID := range renameLinkedFilesFromRecords(renameRecords, path) {
			relatedFiles[fileID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "file",
				Target: fileID,
				Reason: "rename_chain",
			})
		}
	}

	endpoints := networkEndpointsFromIOC(ioc)
	for _, domain := range endpoints.domains {
		for _, networkID := range networkByDomain[domain] {
			relatedNetworks[networkID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "network",
				Target: networkID,
				Reason: "direct_network_field",
			})
		}
	}
	for _, dst := range endpoints.addresses {
		for _, networkID := range networkByAddress[dst] {
			relatedNetworks[networkID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "network",
				Target: networkID,
				Reason: "direct_network_field",
			})
		}
	}
	for _, endpoint := range endpoints.endpoints {
		for _, networkID := range networkByEndpoint[endpoint] {
			relatedNetworks[networkID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "network",
				Target: networkID,
				Reason: "direct_network_endpoint",
			})
		}
	}

	if taintedPID, ok := input.Uint32FromField(ioc.Fields, "tainted_pid"); ok && taintedPID != 0 {
		taintedKey := fmt.Sprintf("pid:%d", taintedPID)
		relatedProcesses[taintedKey] = struct{}{}
		relations = append(relations, model.IOCRelation{
			Kind:   "process",
			Target: taintedKey,
			Reason: "tainted_pid",
		})
	}

	for processKey := range relatedProcesses {
		for _, record := range filesInWindow(byProcess[processKey], ioc.Timestamp, window) {
			relatedFiles[record.ID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "file",
				Target: record.ID,
				Reason: "family_process_window",
			})
		}
		for _, record := range networksInWindow(byProcessNetwork[processKey], ioc.Timestamp, window) {
			relatedNetworks[record.ID] = struct{}{}
			relations = append(relations, model.IOCRelation{
				Kind:   "network",
				Target: record.ID,
				Reason: "family_process_window",
			})
		}
	}

	ioc.RelatedProcessKeys = keysFromSet(relatedProcesses)
	ioc.RelatedFileIDs = keysFromSet(relatedFiles)
	ioc.RelatedNetworkIDs = keysFromSet(relatedNetworks)
	ioc.Relations = dedupeRelations(relations)

	return correlationPatch{IOC: ioc}
}

func buildFileIndex(files map[string]model.FileRecord) map[string][]model.FileRecord {
	byProcess := make(map[string][]model.FileRecord)
	for _, record := range files {
		byProcess[record.ProcessKey] = append(byProcess[record.ProcessKey], record)
	}
	for processKey := range byProcess {
		sort.Slice(byProcess[processKey], func(i, j int) bool {
			return byProcess[processKey][i].Timestamp.Before(byProcess[processKey][j].Timestamp)
		})
	}
	return byProcess
}

func buildNetworkIndex(networks map[string]model.NetworkRecord) map[string][]model.NetworkRecord {
	byProcess := make(map[string][]model.NetworkRecord)
	for _, record := range networks {
		byProcess[record.ProcessKey] = append(byProcess[record.ProcessKey], record)
	}
	for processKey := range byProcess {
		sort.Slice(byProcess[processKey], func(i, j int) bool {
			return byProcess[processKey][i].Timestamp.Before(byProcess[processKey][j].Timestamp)
		})
	}
	return byProcess
}

func filesInWindow(records []model.FileRecord, iocTime time.Time, window time.Duration) []model.FileRecord {
	if len(records) == 0 || iocTime.IsZero() {
		return nil
	}
	lo := iocTime.Add(-window)
	hi := iocTime.Add(window)

	start := sort.Search(len(records), func(i int) bool {
		return !records[i].Timestamp.Before(lo)
	})
	end := sort.Search(len(records), func(i int) bool {
		return records[i].Timestamp.After(hi)
	})
	return records[start:end]
}

func networksInWindow(records []model.NetworkRecord, iocTime time.Time, window time.Duration) []model.NetworkRecord {
	if len(records) == 0 || iocTime.IsZero() {
		return nil
	}
	lo := iocTime.Add(-window)
	hi := iocTime.Add(window)

	start := sort.Search(len(records), func(i int) bool {
		return !records[i].Timestamp.Before(lo)
	})
	end := sort.Search(len(records), func(i int) bool {
		return records[i].Timestamp.After(hi)
	})
	return records[start:end]
}

func renameLinkedFilesFromRecords(renameRecords []model.FileRecord, path string) []string {
	ids := make([]string, 0)
	for _, record := range renameRecords {
		if record.OldPath == path || record.NewPath == path {
			ids = append(ids, record.ID)
		}
	}
	return ids
}

func ancestorChain(nodes map[string]model.ProcessNode, start string) []string {
	if start == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	current := start
	for {
		node, ok := nodes[current]
		if !ok || node.ParentKey == "" {
			break
		}
		parent := node.ParentKey
		if _, exists := seen[parent]; exists {
			break
		}
		seen[parent] = struct{}{}
		out = append(out, parent)
		current = parent
	}
	return out
}

func descendantKeys(
	nodes map[string]model.ProcessNode,
	root string,
	iocTime time.Time,
	window time.Duration,
) []string {
	if root == "" {
		return nil
	}
	out := make([]string, 0)
	for key, node := range nodes {
		if node.ParentKey != root && !isDescendant(nodes, root, key) {
			continue
		}
		if node.ForkTime != nil && withinWindow(*node.ForkTime, iocTime, window) {
			out = append(out, key)
			continue
		}
		if node.ExecTime != nil && withinWindow(*node.ExecTime, iocTime, window) {
			out = append(out, key)
		}
	}
	return out
}

func isDescendant(nodes map[string]model.ProcessNode, ancestor, candidate string) bool {
	current := candidate
	visited := 0
	for current != "" && visited < 64 {
		node, ok := nodes[current]
		if !ok {
			return false
		}
		if node.ParentKey == ancestor {
			return true
		}
		current = node.ParentKey
		visited++
	}
	return false
}

func filePathsFromIOC(ioc model.IOCRecord) []string {
	paths := make([]string, 0)
	for _, name := range []string{
		"file_path", "pathname", "script_path", "executable_path", "old_path", "new_path",
	} {
		if path := input.StringFromField(ioc.Fields, name); path != "" {
			paths = append(paths, path)
		}
	}
	if ioc.DetectedFrom != nil {
		for _, name := range []string{"pathname", "file_path", "old_path", "new_path"} {
			if path := input.StringFromField(ioc.DetectedFrom.Data, name); path != "" {
				paths = append(paths, path)
			}
		}
	}
	return uniqueStrings(paths)
}

type networkEndpointMatch struct {
	domains   []string
	addresses []string
	endpoints []string
}

func networkEndpointsFromIOC(ioc model.IOCRecord) networkEndpointMatch {
	domains := make([]string, 0)
	addresses := make([]string, 0)
	endpoints := make([]string, 0)

	addDomain := func(name string) {
		name = strings.TrimSpace(strings.ToLower(name))
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

	return networkEndpointMatch{
		domains:   uniqueStrings(domains),
		addresses: uniqueStrings(addresses),
		endpoints: uniqueStrings(endpoints),
	}
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

func renameLinkedFiles(builder *graph.Builder, path string) []string {
	return renameLinkedFilesFromRecords(builder.Files().Rename, path)
}

func withinWindow(eventTime, iocTime time.Time, window time.Duration) bool {
	if eventTime.IsZero() || iocTime.IsZero() {
		return false
	}
	diff := eventTime.Sub(iocTime)
	if diff < 0 {
		diff = -diff
	}
	return diff <= window
}

func keysFromSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func dedupeRelations(relations []model.IOCRelation) []model.IOCRelation {
	seen := make(map[string]struct{})
	out := make([]model.IOCRelation, 0, len(relations))
	for _, rel := range relations {
		key := rel.Kind + "|" + rel.Target + "|" + rel.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rel)
	}
	return out
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

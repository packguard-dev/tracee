package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

const (
	FormatJSON  = "json"
	FormatTable = "table"
)

func Encode(format string, out model.Output) ([]byte, error) {
	switch format {
	case "", FormatJSON:
		encoded, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(encoded, '\n'), nil
	case FormatTable:
		return []byte(FormatTableOutput(out)), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q (use json or table)", format)
	}
}

func FormatTableOutput(out model.Output) string {
	if len(out.IOCs) == 0 {
		return renderHeader(out) + sectionTitle("IOCs") + "  (none)\n"
	}

	var b strings.Builder
	b.WriteString(renderHeader(out))

	iocFiles := filesByIOC(out.Files)
	iocNetworks := networksByIOC(out.Networks)
	for i, ioc := range out.IOCs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(sectionTitle("IOCs"))
		b.WriteString(formatIOC(ioc))
		b.WriteString("\n")
		b.WriteString(subsectionTitle("Process trees"))
		b.WriteString(formatProcessTrees(out.ProcessTree, ioc))
		b.WriteString(subsectionTitle("Files"))
		b.WriteString(formatFiles(iocFiles[ioc.ID]))
		b.WriteString(subsectionTitle("Network"))
		b.WriteString(formatNetworks(iocNetworks[ioc.ID]))
		b.WriteString(subsectionTitle("External indicators (pcap)"))
		b.WriteString(formatPcapIndicators(ioc.Pcap))
		b.WriteString(subsectionTitle("External requests (mitm)"))
		b.WriteString(formatMitmRequests(ioc.Mitm))
	}

	return b.String()
}

func renderHeader(out model.Output) string {
	return fmt.Sprintf(
		"tracee-graph-builder report\n"+
			"  generated: %s\n"+
			"  input events: %d\n"+
			"  correlation window: %ds\n"+
			"  ioc count: %d\n\n",
		out.Meta.GeneratedAt.UTC().Format(time.RFC3339),
		out.Meta.InputEvents,
		out.Meta.CorrelationWindowSec,
		len(out.IOCs),
	)
}

func sectionTitle(name string) string {
	line := strings.Repeat("=", 78)
	return fmt.Sprintf("%s\n%s\n%s\n", line, name, line)
}

func subsectionTitle(name string) string {
	line := strings.Repeat("-", 78)
	return fmt.Sprintf("\n%s\n%s\n%s\n", line, name, line)
}

func formatIOC(ioc model.IOCRecord) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  ID:        %s\n", ioc.ID))
	b.WriteString(fmt.Sprintf("  Event:     %s\n", ioc.EventName))
	b.WriteString(fmt.Sprintf("  Timestamp: %s\n", ioc.Timestamp.UTC().Format(time.RFC3339Nano)))
	b.WriteString(fmt.Sprintf("  Process:   %s\n", formatProcessRef(ioc.ProcessKey)))

	for _, field := range iocFieldOrder(ioc.Fields) {
		b.WriteString(fmt.Sprintf("  %s: %s\n", field.name, field.value))
	}

	if ioc.DetectedFrom != nil {
		b.WriteString(fmt.Sprintf("  Detected from: %s (event id %d)\n", ioc.DetectedFrom.Name, ioc.DetectedFrom.ID))
	}

	b.WriteString(formatPayload(ioc.Payload))

	return b.String()
}

func formatPayload(payload *model.PayloadInfo) string {
	if payload == nil {
		return ""
	}

	var b strings.Builder
	if payload.Path != "" {
		b.WriteString(fmt.Sprintf("  Payload:       %s\n", payload.Path))
	}
	if payload.Dev != 0 {
		b.WriteString(fmt.Sprintf("  Payload dev:   %d\n", payload.Dev))
	}
	if payload.Inode != 0 {
		b.WriteString(fmt.Sprintf("  Payload inode: %d\n", payload.Inode))
	}
	if payload.SHA256 != "" {
		b.WriteString(fmt.Sprintf("  Payload sha256: %s\n", payload.SHA256))
	}
	if payload.ArtifactPath != "" {
		b.WriteString(fmt.Sprintf("  Artifact path: %s\n", payload.ArtifactPath))
	}
	if payload.Status != "" {
		b.WriteString(fmt.Sprintf("  Payload status: %s\n", payload.Status))
	}
	return b.String()
}

func formatPcapIndicators(pcapInfo *model.PcapEnrichment) string {
	if pcapInfo == nil || len(pcapInfo.Indicators) == 0 {
		return "  (none)\n"
	}

	var b strings.Builder
	for _, indicator := range pcapInfo.Indicators {
		line := formatExternalIndicator(indicator)
		if line != "" {
			b.WriteString("  " + line + "\n")
		}
	}
	if b.Len() == 0 {
		return "  (none)\n"
	}
	return b.String()
}

func formatMitmRequests(mitmInfo *model.MitmEnrichment) string {
	if mitmInfo == nil || len(mitmInfo.Requests) == 0 {
		return "  (none)\n"
	}

	var b strings.Builder
	for _, request := range mitmInfo.Requests {
		line := formatMitmRequest(request)
		if line != "" {
			b.WriteString("  " + line + "\n")
		}
	}
	if b.Len() == 0 {
		return "  (none)\n"
	}
	return b.String()
}

func formatMitmRequest(request model.MitmRequest) string {
	if request.URL == "" {
		return ""
	}
	parts := []string{
		request.Timestamp.UTC().Format(time.RFC3339),
		request.URL,
	}
	if request.Host != "" {
		parts = append(parts, "host="+request.Host)
	}
	if request.SNI != "" {
		parts = append(parts, "sni="+request.SNI)
	}
	parts = append(parts, fmt.Sprintf("response_bytes=%d", request.ResponseBytes))
	return strings.Join(parts, " ")
}

func formatExternalIndicator(indicator model.ExternalIndicator) string {
	if indicator.Domain != "" {
		if indicator.Port != 0 {
			return fmt.Sprintf(
				"%s (%s:%d %s)",
				indicator.Domain,
				indicator.IP,
				indicator.Port,
				indicator.Protocol,
			)
		}
		return fmt.Sprintf("%s (%s %s)", indicator.Domain, indicator.IP, indicator.Protocol)
	}
	if indicator.Port != 0 {
		if indicator.Protocol != "" {
			return fmt.Sprintf("%s:%d %s", indicator.IP, indicator.Port, indicator.Protocol)
		}
		return fmt.Sprintf("%s:%d", indicator.IP, indicator.Port)
	}
	if indicator.Protocol != "" {
		return fmt.Sprintf("%s %s", indicator.IP, indicator.Protocol)
	}
	return indicator.IP
}

type iocField struct {
	name  string
	value string
}

func iocFieldOrder(fields map[string]any) []iocField {
	if len(fields) == 0 {
		return nil
	}

	preferred := []string{
		"file_path",
		"pathname",
		"script_path",
		"domain",
		"query",
		"base_domain",
		"dst",
		"dst_port",
		"decoy_category",
		"dst_name",
		"src_name",
	}
	seen := make(map[string]struct{}, len(fields))
	out := make([]iocField, 0, len(fields))

	for _, key := range preferred {
		value, ok := fields[key]
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, iocField{name: key, value: formatAny(value)})
	}

	keys := make([]string, 0, len(fields))
	for key := range fields {
		if _, ok := seen[key]; ok {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, iocField{name: key, value: formatAny(fields[key])})
	}

	return out
}

func formatAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		return strings.Join(typed, ", ")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, formatAny(item))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func formatProcessRef(key string) string {
	if key == "" {
		return "(unknown)"
	}
	return key
}

func formatProcessTrees(tree model.ProcessTree, ioc model.IOCRecord) string {
	related := make(map[string]struct{}, len(ioc.RelatedProcessKeys))
	for _, key := range ioc.RelatedProcessKeys {
		related[key] = struct{}{}
	}
	if len(related) == 0 {
		if ioc.ProcessKey != "" {
			related[ioc.ProcessKey] = struct{}{}
		} else {
			return "  (none)\n"
		}
	}

	children := childrenByParent(tree.Nodes)
	roots := displayRoots(tree, related)
	if len(roots) == 0 {
		return "  (none)\n"
	}

	var b strings.Builder
	for i, root := range roots {
		if i > 0 {
			b.WriteString("\n")
		}
		renderProcessTree(&b, tree.Nodes, children, root, related, 0)
	}
	return b.String()
}

func childrenByParent(nodes map[string]model.ProcessNode) map[string][]string {
	children := make(map[string][]string)
	for key, node := range nodes {
		if node.ParentKey == "" {
			continue
		}
		children[node.ParentKey] = append(children[node.ParentKey], key)
	}
	for parent := range children {
		sort.Strings(children[parent])
	}
	return children
}

func displayRoots(tree model.ProcessTree, related map[string]struct{}) []string {
	roots := make([]string, 0)
	seen := make(map[string]struct{})

	for key := range related {
		root := highestRelatedAncestor(tree.Nodes, key, related)
		if root == "" {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}

	sort.Strings(roots)
	if len(roots) > 0 {
		return roots
	}

	for _, root := range tree.Roots {
		if subtreeHasRelated(root, related, tree.Nodes) {
			roots = append(roots, root)
		}
	}
	sort.Strings(roots)
	return roots
}

func highestRelatedAncestor(nodes map[string]model.ProcessNode, key string, related map[string]struct{}) string {
	current := key
	for {
		node, ok := nodes[current]
		if !ok {
			return current
		}
		if node.ParentKey == "" {
			return current
		}
		if _, ok := related[node.ParentKey]; !ok {
			return current
		}
		current = node.ParentKey
	}
}

func subtreeHasRelated(key string, related map[string]struct{}, nodes map[string]model.ProcessNode) bool {
	if _, ok := related[key]; ok {
		return true
	}
	for _, child := range childrenByParent(nodes)[key] {
		if subtreeHasRelated(child, related, nodes) {
			return true
		}
	}
	return false
}

func renderProcessTree(
	b *strings.Builder,
	nodes map[string]model.ProcessNode,
	children map[string][]string,
	key string,
	related map[string]struct{},
	depth int,
) {
	if !subtreeHasRelated(key, related, nodes) {
		return
	}

	indent := strings.Repeat("  ", depth)
	prefix := "|- "
	if depth == 0 {
		prefix = ""
	}
	line, details := formatProcessNode(nodes[key])
	b.WriteString(fmt.Sprintf("%s%s%s\n", indent, prefix, line))
	if details != "" {
		detailIndent := indent
		if depth == 0 {
			detailIndent += "  "
		} else {
			detailIndent += "    "
		}
		b.WriteString(detailIndent + details + "\n")
	}

	for _, child := range children[key] {
		renderProcessTree(b, nodes, children, child, related, depth+1)
	}
}

func formatProcessNode(node model.ProcessNode) (string, string) {
	parts := make([]string, 0, 6)
	parts = append(parts, node.Key)

	if node.PID != 0 {
		parts = append(parts, fmt.Sprintf("pid=%d", node.PID))
	}
	if node.ProcessName != "" {
		parts = append(parts, node.ProcessName)
	}
	if node.ExecutablePath != "" {
		parts = append(parts, fmt.Sprintf("[%s]", node.ExecutablePath))
	}

	line := strings.Join(parts, " ")

	details := make([]string, 0, 4)
	if node.CommandLine != "" {
		details = append(details, fmt.Sprintf("cmd: %s", node.CommandLine))
	} else if len(node.Argv) > 0 {
		details = append(details, fmt.Sprintf("argv: %s", strings.Join(node.Argv, " ")))
	}
	if node.Pwd != "" {
		details = append(details, fmt.Sprintf("cwd: %s", node.Pwd))
	}
	if node.ExecTime != nil {
		details = append(details, fmt.Sprintf("exec: %s", node.ExecTime.UTC().Format(time.RFC3339)))
	}
	if node.ExitTime != nil {
		exitDetail := fmt.Sprintf("exit: %s", node.ExitTime.UTC().Format(time.RFC3339))
		if node.ExitCode != nil {
			exitDetail += fmt.Sprintf(" (code=%d)", *node.ExitCode)
		}
		details = append(details, exitDetail)
	}

	if len(details) == 0 {
		return line, ""
	}
	return line, strings.Join(details, " | ")
}

type iocFileGroups struct {
	Read   []model.FileRecord
	Write  []model.FileRecord
	Delete []model.FileRecord
	Rename []model.FileRecord
}

func filesByIOC(files model.FileGroups) map[string]iocFileGroups {
	out := make(map[string]iocFileGroups)

	add := func(records []model.FileRecord) {
		for _, record := range records {
			for _, iocID := range record.IOCIDs {
				group := out[iocID]
				switch record.Operation {
				case model.FileOpRead:
					group.Read = append(group.Read, record)
				case model.FileOpWrite:
					group.Write = append(group.Write, record)
				case model.FileOpDelete:
					group.Delete = append(group.Delete, record)
				case model.FileOpRename:
					group.Rename = append(group.Rename, record)
				}
				out[iocID] = group
			}
		}
	}

	add(files.Read)
	add(files.Write)
	add(files.Delete)
	add(files.Rename)
	return out
}

func formatFiles(groups iocFileGroups) string {
	var b strings.Builder
	wrote := false

	writeGroup := func(title string, records []model.FileRecord, formatter func(model.FileRecord) string) {
		if len(records) == 0 {
			return
		}
		sort.SliceStable(records, func(i, j int) bool {
			return records[i].Timestamp.Before(records[j].Timestamp)
		})
		b.WriteString(title + ":\n")
		for _, record := range records {
			b.WriteString("  " + formatter(record) + "\n")
		}
		wrote = true
	}

	writeGroup("READ", groups.Read, formatReadFile)
	writeGroup("WRITE", groups.Write, formatWriteFile)
	writeGroup("RENAME", groups.Rename, formatRenameFile)
	writeGroup("DELETE", groups.Delete, formatDeleteFile)

	if !wrote {
		b.WriteString("  (none)\n")
	}
	return b.String()
}

type iocNetworkGroups struct {
	Connect []model.NetworkRecord
}

func networksByIOC(networks model.NetworkGroups) map[string]iocNetworkGroups {
	out := make(map[string]iocNetworkGroups)

	add := func(records []model.NetworkRecord) {
		for _, record := range records {
			for _, iocID := range record.IOCIDs {
				group := out[iocID]
				switch record.Operation {
				case model.NetworkOpConnect:
					group.Connect = append(group.Connect, record)
				}
				out[iocID] = group
			}
		}
	}

	add(networks.Connect)
	return out
}

func formatNetworks(groups iocNetworkGroups) string {
	var b strings.Builder
	wrote := false

	writeGroup := func(title string, records []model.NetworkRecord) {
		if len(records) == 0 {
			return
		}
		sort.SliceStable(records, func(i, j int) bool {
			return records[i].Timestamp.Before(records[j].Timestamp)
		})
		b.WriteString(title + ":\n")
		for _, record := range records {
			b.WriteString("  " + formatConnectRecord(record) + "\n")
		}
		wrote = true
	}

	writeGroup("CONNECT", groups.Connect)

	if !wrote {
		b.WriteString("  (none)\n")
	}
	return b.String()
}

func formatConnectRecord(record model.NetworkRecord) string {
	label := record.Dst
	if len(record.DstDNS) > 0 {
		label = strings.Join(record.DstDNS, ", ") + " -> " + record.Dst
	}
	if record.DstPort != 0 {
		label += fmt.Sprintf(":%d", record.DstPort)
	}
	return fmt.Sprintf(
		"%s  (%s)  process=%s",
		label,
		record.Timestamp.UTC().Format(time.RFC3339),
		record.ProcessKey,
	)
}

func formatReadFile(record model.FileRecord) string {
	return fmt.Sprintf(
		"%s  (%s)  process=%s",
		record.Path,
		record.Timestamp.UTC().Format(time.RFC3339),
		record.ProcessKey,
	)
}

func formatWriteFile(record model.FileRecord) string {
	return formatReadFile(record)
}

func formatDeleteFile(record model.FileRecord) string {
	return formatReadFile(record)
}

func formatRenameFile(record model.FileRecord) string {
	oldPath := record.OldPath
	if oldPath == "" {
		oldPath = record.Path
	}
	newPath := record.NewPath
	if newPath == "" {
		newPath = record.Path
	}
	return fmt.Sprintf(
		"%s -> %s  (%s)  process=%s",
		oldPath,
		newPath,
		record.Timestamp.UTC().Format(time.RFC3339),
		record.ProcessKey,
	)
}

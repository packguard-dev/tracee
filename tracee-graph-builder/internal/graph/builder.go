package graph

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/filter"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/parallel"
)

const (
	devInodeSourceFileModification = "file_modification"
	devInodeSourceFileOpenWrite    = "security_file_open"
	devInodeSourceProcessExec      = "sched_process_exec"
)

type Builder struct {
	nodes                map[string]model.ProcessNode
	files                model.FileGroups
	fileByID             map[string]model.FileRecord
	fileByPath           map[string][]string
	fileByInode          map[string][]string
	pathDevInode         map[string][]model.DevInodeRef
	networks             model.NetworkGroups
	networkByID          map[string]model.NetworkRecord
	networkByDomain      map[string][]string
	networkByAddress     map[string][]string
	networkByEndpoint    map[string][]string
	iocs                 []model.IOCRecord
	iocByID              map[string]int
	nextFileID           int
	whitelist            filter.Whitelist
	whitelistedProcesses map[string]struct{}
}

func NewBuilder() *Builder {
	return NewBuilderWithWhitelist(filter.DefaultWhitelist())
}

// NewBuilderWithWhitelist creates a builder with the given path/command exclusions.
func NewBuilderWithWhitelist(wl filter.Whitelist) *Builder {
	return &Builder{
		nodes:                make(map[string]model.ProcessNode),
		fileByID:             make(map[string]model.FileRecord),
		fileByPath:           make(map[string][]string),
		fileByInode:          make(map[string][]string),
		pathDevInode:         make(map[string][]model.DevInodeRef),
		networkByID:          make(map[string]model.NetworkRecord),
		networkByDomain:      make(map[string][]string),
		networkByAddress:     make(map[string][]string),
		networkByEndpoint:    make(map[string][]string),
		iocByID:              make(map[string]int),
		whitelist:            wl,
		whitelistedProcesses: make(map[string]struct{}),
	}
}

func (b *Builder) Ingest(events []model.NormalizedEvent) {
	b.IngestParallel(events, parallel.WorkerCount(0))
}

// IngestParallel builds the graph using a sequential lifecycle pass and parallel
// file/IOC passes.
func (b *Builder) IngestParallel(events []model.NormalizedEvent, workers int) {
	if len(events) == 0 {
		return
	}

	sorted := append([]model.NormalizedEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Index < sorted[j].Index
	})

	for _, ev := range sorted {
		b.ensureProcessNode(ev)
		switch ev.EventName {
		case "sched_process_fork":
			b.handleFork(ev)
		case "sched_process_exec":
			b.handleExec(ev)
		case "sched_process_exit":
			b.handleExit(ev)
		}
	}

	workers = parallel.WorkerCount(workers)
	fileResults := make([]*model.FileRecord, len(sorted))
	_ = parallel.Run(context.Background(), workers, len(sorted), func(i int) error {
		if record := buildFileRecord(sorted[i], b.whitelist, b.whitelistedProcesses); record != nil {
			fileResults[i] = record
		}
		return nil
	})
	for _, record := range fileResults {
		if record != nil {
			b.addFileRecord(*record)
		}
	}

	networkResults := make([]*model.NetworkRecord, len(sorted))
	_ = parallel.Run(context.Background(), workers, len(sorted), func(i int) error {
		if record := buildNetworkRecord(sorted[i], b.whitelist, b.whitelistedProcesses); record != nil {
			networkResults[i] = record
		}
		return nil
	})
	for _, record := range networkResults {
		if record != nil {
			b.addNetworkRecord(*record)
		}
	}

	iocResults := make([]*model.IOCRecord, len(sorted))
	_ = parallel.Run(context.Background(), workers, len(sorted), func(i int) error {
		if record := buildIOCRecord(sorted[i]); record != nil {
			iocResults[i] = record
		}
		return nil
	})
	for _, record := range iocResults {
		if record == nil {
			continue
		}
		b.iocs = append(b.iocs, *record)
		b.iocByID[record.ID] = len(b.iocs) - 1
		if node, ok := b.nodes[record.ProcessKey]; ok {
			node.IOCIDs = appendUnique(node.IOCIDs, record.ID)
			b.nodes[record.ProcessKey] = node
		}
	}
}

func (b *Builder) ensureProcessNode(ev model.NormalizedEvent) {
	if ev.ProcessKey == "" {
		return
	}
	node, ok := b.nodes[ev.ProcessKey]
	if !ok {
		node = model.ProcessNode{Key: ev.ProcessKey}
	}
	if ev.PID != 0 {
		node.PID = ev.PID
	}
	if ev.HostPID != 0 {
		node.HostPID = ev.HostPID
	}
	if ev.ParentKey != "" {
		node.ParentKey = ev.ParentKey
	}
	if ev.ProcessName != "" {
		node.ProcessName = ev.ProcessName
	}
	if ev.ExecutablePath != "" && node.ExecutablePath == "" {
		node.ExecutablePath = ev.ExecutablePath
	}
	if ev.ContainerID != "" {
		node.ContainerID = ev.ContainerID
	}
	if len(ev.AncestorKeys) > 0 {
		node.AncestorKeys = append([]string(nil), ev.AncestorKeys...)
	}
	b.nodes[ev.ProcessKey] = node
}

func (b *Builder) handleFork(ev model.NormalizedEvent) {
	parentPID := uint32(input.IntFromField(ev.Fields, "parent_pid"))
	childPID := uint32(input.IntFromField(ev.Fields, "child_pid"))
	parentKey := processKeyFromFork(ev, parentPID, true)
	childKey := processKeyFromFork(ev, childPID, false)

	if parentKey != "" {
		parent := b.nodes[parentKey]
		parent.Key = parentKey
		if parentPID != 0 {
			parent.PID = parentPID
		}
		b.nodes[parentKey] = parent
	}

	child := b.nodes[childKey]
	child.Key = childKey
	if childPID != 0 {
		child.PID = childPID
	}
	if parentKey != "" {
		child.ParentKey = parentKey
	}
	if !ev.Timestamp.IsZero() {
		ts := ev.Timestamp
		child.ForkTime = &ts
	}
	b.nodes[childKey] = child
}

func processKeyFromFork(ev model.NormalizedEvent, pid uint32, parent bool) string {
	if parent {
		if ev.ParentKey != "" {
			return ev.ParentKey
		}
		if pid != 0 {
			return fmt.Sprintf("pid:%d", pid)
		}
		return ""
	}
	if ev.ProcessKey != "" {
		return ev.ProcessKey
	}
	if pid != 0 {
		return fmt.Sprintf("pid:%d", pid)
	}
	return ""
}

func (b *Builder) handleExec(ev model.NormalizedEvent) {
	node := b.nodes[ev.ProcessKey]
	node.Key = ev.ProcessKey

	pathname := input.StringFromField(ev.Fields, "pathname")
	cmdpath := input.StringFromField(ev.Fields, "cmdpath")
	if pathname != "" {
		node.ExecutablePath = pathname
	} else if cmdpath != "" {
		node.ExecutablePath = cmdpath
	} else if ev.ExecutablePath != "" {
		node.ExecutablePath = ev.ExecutablePath
	}

	argv := input.StringSliceFromField(ev.Fields, "argv")
	if len(argv) > 0 {
		node.Argv = argv
		node.CommandLine = strings.TrimSpace(strings.Join(argv, " "))
	}
	if node.CommandLine == "" && cmdpath != "" {
		node.CommandLine = cmdpath
	}

	pwd := input.StringFromField(ev.Fields, "pwd")
	if pwd != "" {
		node.Pwd = pwd
	}
	if !ev.Timestamp.IsZero() {
		ts := ev.Timestamp
		node.ExecTime = &ts
	}
	if b.whitelist.IsCommandExcluded(node.ExecutablePath, node.CommandLine, node.Argv) {
		b.whitelistedProcesses[ev.ProcessKey] = struct{}{}
	}
	if node.ExecutablePath != "" {
		if dev, okDev := input.Uint32FromField(ev.Fields, "dev"); okDev {
			if inode, okInode := input.Uint64FromField(ev.Fields, "inode"); okInode && dev != 0 && inode != 0 {
				b.indexPathDevInode(node.ExecutablePath, dev, inode, devInodeSourceProcessExec)
			}
		}
	}
	b.nodes[ev.ProcessKey] = node
}

func (b *Builder) handleExit(ev model.NormalizedEvent) {
	node := b.nodes[ev.ProcessKey]
	node.Key = ev.ProcessKey
	if code, ok := input.Int32FromField(ev.Fields, "exit_code"); ok {
		node.ExitCode = &code
	}
	if signal, ok := input.Int32FromField(ev.Fields, "signal_code"); ok {
		node.SignalCode = &signal
	}
	if !ev.Timestamp.IsZero() {
		ts := ev.Timestamp
		node.ExitTime = &ts
	}
	b.nodes[ev.ProcessKey] = node
}

func (b *Builder) handleFileOpen(ev model.NormalizedEvent) {
	path := input.StringFromField(ev.Fields, "pathname", "syscall_pathname")
	if path == "" {
		return
	}
	flagsRaw := ev.Fields["flags"]
	op, flagsText := classifyOpenFlags(flagsRaw)
	if op == "" {
		return
	}
	record := b.newFileRecord(ev, op, path, "", "", "security_file_open")
	record.Flags = flagsText
	if dev, ok := input.Uint32FromField(ev.Fields, "dev"); ok {
		record.Dev = dev
	}
	if inode, ok := input.Uint64FromField(ev.Fields, "inode"); ok {
		record.Inode = inode
	}
	b.addFileRecord(record)
}

func (b *Builder) handleFileModification(ev model.NormalizedEvent) {
	path := input.StringFromField(ev.Fields, "file_path")
	if path == "" {
		return
	}
	record := b.newFileRecord(ev, model.FileOpWrite, path, "", "", "file_modification")
	if dev, ok := input.Uint32FromField(ev.Fields, "dev"); ok {
		record.Dev = dev
	}
	if inode, ok := input.Uint64FromField(ev.Fields, "inode"); ok {
		record.Inode = inode
	}
	b.addFileRecord(record)
}

func (b *Builder) handleUnlink(ev model.NormalizedEvent) {
	path := input.StringFromField(ev.Fields, "pathname")
	if path == "" {
		return
	}
	record := b.newFileRecord(ev, model.FileOpDelete, path, "", "", "security_inode_unlink")
	if dev, ok := input.Uint32FromField(ev.Fields, "dev"); ok {
		record.Dev = dev
	}
	if inode, ok := input.Uint64FromField(ev.Fields, "inode"); ok {
		record.Inode = inode
	}
	b.addFileRecord(record)
}

func (b *Builder) handleRename(ev model.NormalizedEvent) {
	oldPath := input.StringFromField(ev.Fields, "old_path")
	newPath := input.StringFromField(ev.Fields, "new_path")
	if oldPath == "" && newPath == "" {
		return
	}
	record := b.newFileRecord(ev, model.FileOpRename, newPath, oldPath, newPath, "security_inode_rename")
	b.addFileRecord(record)
}

func (b *Builder) handleIOC(ev model.NormalizedEvent) {
	record := buildIOCRecord(ev)
	if record == nil {
		return
	}
	b.iocs = append(b.iocs, *record)
	b.iocByID[record.ID] = len(b.iocs) - 1

	if node, ok := b.nodes[ev.ProcessKey]; ok {
		node.IOCIDs = appendUnique(node.IOCIDs, record.ID)
		b.nodes[ev.ProcessKey] = node
	}
}

func buildFileRecord(
	ev model.NormalizedEvent,
	wl filter.Whitelist,
	whitelistedProcesses map[string]struct{},
) *model.FileRecord {
	if _, ok := whitelistedProcesses[ev.ProcessKey]; ok {
		return nil
	}

	switch ev.EventName {
	case "security_file_open":
		path := input.StringFromField(ev.Fields, "pathname", "syscall_pathname")
		if path == "" {
			return nil
		}
		if wl.ShouldExcludeFileRecord(path, "", "") {
			return nil
		}
		flagsRaw := ev.Fields["flags"]
		op, flagsText := classifyOpenFlags(flagsRaw)
		if op == "" {
			return nil
		}
		record := &model.FileRecord{
			ID:         fileRecordID(ev.Index),
			Operation:  op,
			Path:       path,
			Timestamp:  ev.Timestamp,
			ProcessKey: ev.ProcessKey,
			EventName:  "security_file_open",
			Flags:      flagsText,
		}
		if dev, ok := input.Uint32FromField(ev.Fields, "dev"); ok {
			record.Dev = dev
		}
		if inode, ok := input.Uint64FromField(ev.Fields, "inode"); ok {
			record.Inode = inode
		}
		return record
	case "file_modification":
		path := input.StringFromField(ev.Fields, "file_path")
		if path == "" {
			return nil
		}
		if wl.ShouldExcludeFileRecord(path, "", "") {
			return nil
		}
		record := &model.FileRecord{
			ID:         fileRecordID(ev.Index),
			Operation:  model.FileOpWrite,
			Path:       path,
			Timestamp:  ev.Timestamp,
			ProcessKey: ev.ProcessKey,
			EventName:  "file_modification",
		}
		if dev, ok := input.Uint32FromField(ev.Fields, "dev"); ok {
			record.Dev = dev
		}
		if inode, ok := input.Uint64FromField(ev.Fields, "inode"); ok {
			record.Inode = inode
		}
		return record
	case "security_inode_unlink":
		path := input.StringFromField(ev.Fields, "pathname")
		if path == "" {
			return nil
		}
		if wl.ShouldExcludeFileRecord(path, "", "") {
			return nil
		}
		record := &model.FileRecord{
			ID:         fileRecordID(ev.Index),
			Operation:  model.FileOpDelete,
			Path:       path,
			Timestamp:  ev.Timestamp,
			ProcessKey: ev.ProcessKey,
			EventName:  "security_inode_unlink",
		}
		if dev, ok := input.Uint32FromField(ev.Fields, "dev"); ok {
			record.Dev = dev
		}
		if inode, ok := input.Uint64FromField(ev.Fields, "inode"); ok {
			record.Inode = inode
		}
		return record
	case "security_inode_rename":
		oldPath := input.StringFromField(ev.Fields, "old_path")
		newPath := input.StringFromField(ev.Fields, "new_path")
		if oldPath == "" && newPath == "" {
			return nil
		}
		if wl.ShouldExcludeFileRecord(newPath, oldPath, newPath) {
			return nil
		}
		return &model.FileRecord{
			ID:         fileRecordID(ev.Index),
			Operation:  model.FileOpRename,
			Path:       newPath,
			OldPath:    oldPath,
			NewPath:    newPath,
			Timestamp:  ev.Timestamp,
			ProcessKey: ev.ProcessKey,
			EventName:  "security_inode_rename",
		}
	default:
		return nil
	}
}

func buildNetworkRecord(
	ev model.NormalizedEvent,
	wl filter.Whitelist,
	whitelistedProcesses map[string]struct{},
) *model.NetworkRecord {
	if ev.EventName != "net_tcp_connect" {
		return nil
	}
	if _, ok := whitelistedProcesses[ev.ProcessKey]; ok {
		return nil
	}

	dst := input.StringFromField(ev.Fields, "dst")
	if dst == "" {
		return nil
	}

	dstDNS := input.StringSliceFromField(ev.Fields, "dst_dns")
	if wl.ShouldExcludeNetworkRecord(dstDNS) {
		return nil
	}

	dstPort, _ := input.Int32FromField(ev.Fields, "dst_port")

	return &model.NetworkRecord{
		ID:         networkRecordID(ev.Index),
		Operation:  model.NetworkOpConnect,
		Dst:        dst,
		DstPort:    dstPort,
		DstDNS:     dstDNS,
		Timestamp:  ev.Timestamp,
		ProcessKey: ev.ProcessKey,
		EventName:  "net_tcp_connect",
	}
}

func buildIOCRecord(ev model.NormalizedEvent) *model.IOCRecord {
	if !ev.IsIOC {
		return nil
	}
	return &model.IOCRecord{
		ID:           iocRecordID(ev.Index),
		Timestamp:    ev.Timestamp,
		EventName:    ev.EventName,
		ProcessKey:   ev.ProcessKey,
		Fields:       copyFields(ev.Fields),
		DetectedFrom: ev.DetectedFrom,
	}
}

func fileRecordID(index int) string {
	return fmt.Sprintf("file-%d", index)
}

func networkRecordID(index int) string {
	return fmt.Sprintf("net-%d", index)
}

func iocRecordID(index int) string {
	return fmt.Sprintf("ioc-%d", index)
}

func (b *Builder) newFileRecord(
	ev model.NormalizedEvent,
	op, path, oldPath, newPath, eventName string,
) model.FileRecord {
	b.nextFileID++
	return model.FileRecord{
		ID:         fmt.Sprintf("file-%d", b.nextFileID),
		Operation:  op,
		Path:       path,
		OldPath:    oldPath,
		NewPath:    newPath,
		Timestamp:  ev.Timestamp,
		ProcessKey: ev.ProcessKey,
		EventName:  eventName,
	}
}

func (b *Builder) addFileRecord(record model.FileRecord) {
	b.fileByID[record.ID] = record
	if record.Path != "" {
		b.fileByPath[record.Path] = append(b.fileByPath[record.Path], record.ID)
	}
	if record.OldPath != "" {
		b.fileByPath[record.OldPath] = append(b.fileByPath[record.OldPath], record.ID)
	}
	if record.Dev != 0 && record.Inode != 0 {
		key := inodeKey(record.Dev, record.Inode)
		b.fileByInode[key] = append(b.fileByInode[key], record.ID)
	}

	switch record.Operation {
	case model.FileOpRead:
		b.files.Read = append(b.files.Read, record)
	case model.FileOpWrite:
		b.files.Write = append(b.files.Write, record)
		if record.Dev != 0 && record.Inode != 0 && record.Path != "" {
			source := record.EventName
			if source == "" {
				source = devInodeSourceFileModification
			}
			b.indexPathDevInode(record.Path, record.Dev, record.Inode, source)
		}
	case model.FileOpDelete:
		b.files.Delete = append(b.files.Delete, record)
	case model.FileOpRename:
		b.files.Rename = append(b.files.Rename, record)
	}
}

func (b *Builder) addNetworkRecord(record model.NetworkRecord) {
	b.networkByID[record.ID] = record
	for _, domain := range record.DstDNS {
		if domain == "" {
			continue
		}
		b.networkByDomain[domain] = append(b.networkByDomain[domain], record.ID)
	}
	if record.Dst != "" {
		b.networkByAddress[record.Dst] = append(b.networkByAddress[record.Dst], record.ID)
		key := networkEndpointKey(record.Dst, record.DstPort)
		b.networkByEndpoint[key] = append(b.networkByEndpoint[key], record.ID)
	}

	if record.Operation == model.NetworkOpConnect {
		b.networks.Connect = append(b.networks.Connect, record)
	}
}

func classifyOpenFlags(flagsRaw any) (operation, flagsText string) {
	switch flags := flagsRaw.(type) {
	case string:
		flagsText = flags
		upper := strings.ToUpper(flags)
		if strings.Contains(upper, "O_WRONLY") {
			return model.FileOpWrite, flagsText
		}
		if strings.Contains(upper, "O_RDWR") {
			return model.FileOpRead, flagsText
		}
		if strings.Contains(upper, "O_RDONLY") {
			return model.FileOpRead, flagsText
		}
		return "", flagsText
	case int32:
		return classifyOpenFlagsInt(int(flags))
	case int64:
		return classifyOpenFlagsInt(int(flags))
	case float64:
		return classifyOpenFlagsInt(int(flags))
	default:
		return "", ""
	}
}

func classifyOpenFlagsInt(flags int) (operation, flagsText string) {
	flagsText = strconv.Itoa(flags)
	accessMode := uint64(flags) & syscall.O_ACCMODE
	switch accessMode {
	case syscall.O_WRONLY:
		return model.FileOpWrite, flagsText
	case syscall.O_RDWR:
		return model.FileOpRead, flagsText
	case syscall.O_RDONLY:
		return model.FileOpRead, flagsText
	default:
		return "", flagsText
	}
}

func (b *Builder) Nodes() map[string]model.ProcessNode { return b.nodes }                                                      
                                                                                                                                                                                                                                                                     func (b *Builder) Files() model.FileGroups { return b.files }

func (b *Builder) Networks() model.NetworkGroups { return b.networks }

func (b *Builder) UpdateFileRecord(record model.FileRecord) {
	b.fileByID[record.ID] = record
	switch record.Operation {
	case model.FileOpRead:
		b.files.Read = replaceRecord(b.files.Read, record)
	case model.FileOpWrite:
		b.files.Write = replaceRecord(b.files.Write, record)
	case model.FileOpDelete:
		b.files.Delete = replaceRecord(b.files.Delete, record)
	case model.FileOpRename:
		b.files.Rename = replaceRecord(b.files.Rename, record)
	}
}

func replaceRecord(records []model.FileRecord, updated model.FileRecord) []model.FileRecord {
	for i, record := range records {
		if record.ID == updated.ID {
			records[i] = updated
			return records
		}
	}
	return records
}

func (b *Builder) UpdateNetworkRecord(record model.NetworkRecord) {
	b.networkByID[record.ID] = record
	if record.Operation == model.NetworkOpConnect {
		b.networks.Connect = replaceNetworkRecord(b.networks.Connect, record)
	}
}

func replaceNetworkRecord(records []model.NetworkRecord, updated model.NetworkRecord) []model.NetworkRecord {
	for i, record := range records {
		if record.ID == updated.ID {
			records[i] = updated
			return records
		}
	}
	return records
}

func (b *Builder) FileByID() map[string]model.FileRecord {
	return b.fileByID
}
func (b *Builder) FileByPath() map[string][]string { return b.fileByPath }
func (b *Builder) FileByInode() map[string][]string {
	return b.fileByInode
}

func (b *Builder) PathDevInodeIndex() map[string][]model.DevInodeRef {
	out := make(map[string][]model.DevInodeRef, len(b.pathDevInode))
	for path, refs := range b.pathDevInode {
		out[path] = append([]model.DevInodeRef(nil), refs...)
	}
	return out
}

func (b *Builder) indexPathDevInode(path string, dev uint32, inode uint64, source string) {
	if path == "" || dev == 0 || inode == 0 {
		return
	}
	refs := b.pathDevInode[path]
	for _, ref := range refs {
		if ref.Dev == dev && ref.Inode == inode {
			if devInodePriority(source) < devInodePriority(ref.Source) {
				ref.Source = source
				for i := range refs {
					if refs[i].Dev == dev && refs[i].Inode == inode {
						refs[i] = ref
						break
					}
				}
				b.pathDevInode[path] = sortDevInodeRefs(refs)
			}
			return
		}
	}
	refs = append(refs, model.DevInodeRef{Dev: dev, Inode: inode, Source: source})
	b.pathDevInode[path] = sortDevInodeRefs(refs)
}

func devInodePriority(source string) int {
	switch source {
	case devInodeSourceFileModification:
		return 0
	case devInodeSourceFileOpenWrite:
		return 1
	case devInodeSourceProcessExec:
		return 2
	default:
		return 3
	}
}

func sortDevInodeRefs(refs []model.DevInodeRef) []model.DevInodeRef {
	sort.SliceStable(refs, func(i, j int) bool {
		pi := devInodePriority(refs[i].Source)
		pj := devInodePriority(refs[j].Source)
		if pi != pj {
			return pi < pj
		}
		if refs[i].Dev != refs[j].Dev {
			return refs[i].Dev < refs[j].Dev
		}
		return refs[i].Inode < refs[j].Inode
	})
	return refs
}

func (b *Builder) NetworkByID() map[string]model.NetworkRecord {
	return b.networkByID
}

func (b *Builder) NetworkByDomain() map[string][]string {
	return b.networkByDomain
}

func (b *Builder) NetworkByAddress() map[string][]string {
	return b.networkByAddress
}

func (b *Builder) NetworkByEndpoint() map[string][]string {
	return b.networkByEndpoint
}

func (b *Builder) IOCs() []model.IOCRecord { return b.iocs }

func (b *Builder) SetIOCs(iocs []model.IOCRecord) {
	b.iocs = iocs
}

func (b *Builder) Roots() []string {
	childParents := make(map[string]struct{})
	for _, node := range b.nodes {
		if node.ParentKey != "" {
			childParents[node.Key] = struct{}{}
		}
	}
	roots := make([]string, 0)
	for key := range b.nodes {
		node := b.nodes[key]
		if node.ParentKey == "" {
			roots = append(roots, key)
			continue
		}
		if _, ok := b.nodes[node.ParentKey]; !ok {
			roots = append(roots, key)
		}
	}
	if len(roots) == 0 {
		for key := range b.nodes {
			roots = append(roots, key)
		}
	}
	return roots
}

func inodeKey(dev uint32, inode uint64) string {
	return fmt.Sprintf("%d:%d", dev, inode)
}

func networkEndpointKey(dst string, port int32) string {
	return fmt.Sprintf("%s:%d", dst, port)
}

func copyFields(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
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

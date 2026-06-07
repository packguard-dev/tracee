package payload

import (
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

var interpreterNames = map[string]struct{}{
	"python":     {},
	"python2":    {},
	"python3":    {},
	"node":       {},
	"nodejs":     {},
	"bash":       {},
	"sh":         {},
	"dash":       {},
	"perl":       {},
	"ruby":       {},
	"php":        {},
	"lua":        {},
	"pwsh":       {},
	"powershell": {},
}

// ResolvePath returns the payload file path for an IOC process.
func ResolvePath(node model.ProcessNode) string {
	executable := node.ExecutablePath
	argv := node.Argv

	if isInterpreter(executable) && len(argv) >= 2 {
		for _, arg := range argv[1:] {
			if arg == "" || strings.HasPrefix(arg, "-") {
				continue
			}
			return resolvePathArg(arg, node.Pwd)
		}
	}

	if len(argv) > 0 && strings.HasPrefix(argv[0], "/") {
		return argv[0]
	}

	if executable != "" {
		return executable
	}

	return ""
}

// ResolveDevInode returns dev/inode candidates for a payload path, highest priority first.
func ResolveDevInode(pathIndex map[string][]model.DevInodeRef, payloadPath string) []model.DevInodeRef {
	if payloadPath == "" || pathIndex == nil {
		return nil
	}
	refs, ok := pathIndex[payloadPath]
	if !ok || len(refs) == 0 {
		return nil
	}
	out := make([]model.DevInodeRef, len(refs))
	copy(out, refs)
	sort.SliceStable(out, func(i, j int) bool {
		pi := devInodePriority(out[i].Source)
		pj := devInodePriority(out[j].Source)
		if pi != pj {
			return pi < pj
		}
		if out[i].Dev != out[j].Dev {
			return out[i].Dev < out[j].Dev
		}
		return out[i].Inode < out[j].Inode
	})
	return out
}

func devInodePriority(source string) int {
	switch source {
	case "file_modification":
		return 0
	case "security_file_open":
		return 1
	case "sched_process_exec":
		return 2
	default:
		return 3
	}
}

// EnrichIOC fills PayloadInfo on an IOC record from process tree and path index.
func EnrichIOC(
	ioc model.IOCRecord,
	nodes map[string]model.ProcessNode,
	pathIndex map[string][]model.DevInodeRef,
) model.IOCRecord {
	node, ok := nodes[ioc.ProcessKey]
	if !ok {
		ioc.Payload = &model.PayloadInfo{Status: model.PayloadStatusNoPath}
		return ioc
	}

	payloadPath := ResolvePath(node)
	if payloadPath == "" {
		ioc.Payload = &model.PayloadInfo{Status: model.PayloadStatusNoPath}
		return ioc
	}

	info := &model.PayloadInfo{Path: payloadPath}
	candidates := ResolveDevInode(pathIndex, payloadPath)
	if len(candidates) == 0 {
		info.Status = model.PayloadStatusNotInEvents
		ioc.Payload = info
		return ioc
	}

	info.Dev = candidates[0].Dev
	info.Inode = candidates[0].Inode
	ioc.Payload = info
	return ioc
}

func isInterpreter(executable string) bool {
	if executable == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(executable))
	if _, ok := interpreterNames[base]; ok {
		return true
	}
	for name := range interpreterNames {
		if strings.HasPrefix(base, name) {
			return true
		}
	}
	return false
}

func resolvePathArg(arg, pwd string) string {
	if strings.HasPrefix(arg, "/") {
		return path.Clean(arg)
	}
	if pwd == "" {
		return arg
	}
	return path.Clean(filepath.Join(pwd, arg))
}

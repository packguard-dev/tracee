package detectors

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/elf"
	"github.com/aquasecurity/tracee/common/parsers"
)

// unpackExecChainWindow matches suspicionWindow used by other detectors: correlations expire.
const unpackExecChainWindow = 5 * time.Minute

type unpackElfDrop struct {
	hadWriteAt time.Time
}

type unpackPidState struct {
	elfWrites map[string]unpackElfDrop
	chmodExec map[string]struct{}
}

var (
	unpackElfChmodMu sync.Mutex
	unpackElfChmod   = make(map[uint32]*unpackPidState)
)

func unpackGetOrCreate(pid uint32) *unpackPidState {
	unpackElfChmodMu.Lock()
	defer unpackElfChmodMu.Unlock()

	s, ok := unpackElfChmod[pid]
	if !ok {
		s = &unpackPidState{
			elfWrites: make(map[string]unpackElfDrop),
			chmodExec: make(map[string]struct{}),
		}
		unpackElfChmod[pid] = s
	}
	return s
}

func unpackNormalizePath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func unpackSyscallSucceeded(event *v1beta1.Event) bool {
	rv, ok := v1beta1.GetData[int64](event, "returnValue")
	if !ok {
		return true
	}
	return rv == 0
}

// modeAddsExecuteBits interprets chmod mode fields from Tracee events.
func modeAddsExecuteBits(event *v1beta1.Event) bool {
	if v, ok := v1beta1.GetData[uint32](event, "mode"); ok {
		return (v & 0o111) != 0
	}
	if v, ok := v1beta1.GetData[int32](event, "mode"); ok {
		return (uint32(v) & 0o111) != 0
	}
	if v, ok := v1beta1.GetData[int64](event, "mode"); ok {
		return (uint32(v) & 0o111) != 0
	}
	return false
}

func unpackEvictExpired(now time.Time) {
	unpackElfChmodMu.Lock()
	defer unpackElfChmodMu.Unlock()

	for pid, st := range unpackElfChmod {
		for p, rec := range st.elfWrites {
			if now.Sub(rec.hadWriteAt) > unpackExecChainWindow {
				delete(st.elfWrites, p)
				delete(st.chmodExec, p)
			}
		}
		if len(st.elfWrites) == 0 && len(st.chmodExec) == 0 {
			delete(unpackElfChmod, pid)
		}
	}
}

func init() {
	register(&UnpackElfChmodExecute{})
}

// UnpackElfChmodExecute detects a second-stage style chain: an ELF is written to disk
// (magic_write), optional permission change adds execute bits (chmod / fchmodat /
// chmod_common), then the same process executes that file. fchmod is correlated only
// when this PID has exactly one pending ELF drop path to reduce ambiguity.
type UnpackElfChmodExecute struct {
	logger detection.Logger
}

func (d *UnpackElfChmodExecute) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-005",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{Name: "magic_write", Dependency: detection.DependencyRequired},
				{Name: "chmod", Dependency: detection.DependencyRequired},
				{Name: "fchmodat", Dependency: detection.DependencyRequired},
				{Name: "chmod_common", Dependency: detection.DependencyRequired},
				{Name: "fchmod", Dependency: detection.DependencyRequired},
				{Name: "sched_process_exec", Dependency: detection.DependencyRequired},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "unpack_elf_chmod_execute",
			Description: "ELF written to disk, made executable, then executed by the same process",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "file_path", Type: "const char*"},
				{Name: "trigger", Type: "const char*"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Unpacked executable chmod and run",
			Description: "A binary was written, execute permission was added, and the file was run. This pattern often follows decompressing a payload before execution.",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Defense Evasion",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1140",
					Name: "Deobfuscate/Decode Files or Information",
				},
			},
			Properties: map[string]string{
				"Category": "defense-evasion",
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *UnpackElfChmodExecute) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Infow("UnpackElfChmodExecute detector initialized")
	return nil
}

func (d *UnpackElfChmodExecute) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	_ = ctx
	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return nil, nil
	}

	unpackEvictExpired(time.Now())

	switch event.Name {
	case "magic_write":
		return d.handleMagicWrite(pid, event)
	case "chmod", "fchmodat", "chmod_common":
		return d.handlePathChmod(pid, event)
	case "fchmod":
		return d.handleFchmod(pid, event)
	case "sched_process_exec":
		return d.handleExec(pid, event)
	}
	return nil, nil
}

func (d *UnpackElfChmodExecute) handleMagicWrite(
	pid uint32,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	header, ok := v1beta1.GetData[[]byte](event, "bytes")
	if !ok || len(header) == 0 || !elf.IsElf(header) {
		return nil, nil
	}
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil || pathname == "" {
		return nil, nil
	}
	if parsers.IsMemoryPath(pathname) {
		return nil, nil
	}
	key := unpackNormalizePath(pathname)
	if key == "" {
		return nil, nil
	}

	st := unpackGetOrCreate(pid)
	unpackElfChmodMu.Lock()
	st.elfWrites[key] = unpackElfDrop{hadWriteAt: time.Now()}
	delete(st.chmodExec, key)
	unpackElfChmodMu.Unlock()

	d.logger.Debugw("UnpackElfChmodExecute recorded ELF magic_write",
		"pid", pid, "path", key)
	return nil, nil
}

func (d *UnpackElfChmodExecute) handlePathChmod(
	pid uint32,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	if !unpackSyscallSucceeded(event) {
		return nil, nil
	}
	if !modeAddsExecuteBits(event) {
		return nil, nil
	}
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil || pathname == "" {
		return nil, nil
	}
	key := unpackNormalizePath(pathname)
	if key == "" {
		return nil, nil
	}

	st := unpackGetOrCreate(pid)
	unpackElfChmodMu.Lock()
	rec, hasElf := st.elfWrites[key]
	if !hasElf || time.Since(rec.hadWriteAt) > unpackExecChainWindow {
		unpackElfChmodMu.Unlock()
		return nil, nil
	}
	st.chmodExec[key] = struct{}{}
	unpackElfChmodMu.Unlock()

	d.logger.Debugw("UnpackElfChmodExecute recorded chmod with execute bits",
		"pid", pid, "path", key, "event", event.Name)
	return nil, nil
}

func (d *UnpackElfChmodExecute) handleFchmod(
	pid uint32,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	if !unpackSyscallSucceeded(event) {
		return nil, nil
	}
	if !modeAddsExecuteBits(event) {
		return nil, nil
	}

	st := unpackGetOrCreate(pid)
	unpackElfChmodMu.Lock()
	now := time.Now()
	var pendingPaths []string
	for p, rec := range st.elfWrites {
		if now.Sub(rec.hadWriteAt) > unpackExecChainWindow {
			continue
		}
		pendingPaths = append(pendingPaths, p)
	}
	if len(pendingPaths) != 1 {
		unpackElfChmodMu.Unlock()
		return nil, nil
	}
	solePath := pendingPaths[0]
	st.chmodExec[solePath] = struct{}{}
	unpackElfChmodMu.Unlock()

	d.logger.Debugw("UnpackElfChmodExecute correlated fchmod to sole ELF path",
		"pid", pid, "path", solePath)
	return nil, nil
}

func (d *UnpackElfChmodExecute) handleExec(
	pid uint32,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	execPath := extractStringField(event, "pathname")
	if execPath == "" {
		execPath = extractStringField(event, "cmdpath")
	}
	if execPath == "" || parsers.IsMemoryPath(execPath) {
		return nil, nil
	}
	key := unpackNormalizePath(execPath)
	if key == "" {
		return nil, nil
	}

	st := unpackGetOrCreate(pid)
	unpackElfChmodMu.Lock()
	rec, hadWrite := st.elfWrites[key]
	_, hadChmod := st.chmodExec[key]
	if !hadWrite || !hadChmod || time.Since(rec.hadWriteAt) > unpackExecChainWindow {
		unpackElfChmodMu.Unlock()
		return nil, nil
	}
	delete(st.elfWrites, key)
	delete(st.chmodExec, key)
	if len(st.elfWrites) == 0 && len(st.chmodExec) == 0 {
		delete(unpackElfChmod, pid)
	}
	unpackElfChmodMu.Unlock()

	d.logger.Infow("UnpackELF chmod then execute",
		"pid", pid, "path", key)

	go sendPauseSignal(event.GetWorkload().GetContainer().GetId(), "TRC-005", key)

	return detection.DetectedWithData(
		[]*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", key),
			v1beta1.NewStringValue("trigger", "sched_process_exec"),
		},
	), nil
}

func (d *UnpackElfChmodExecute) Close() error {
	d.logger.Debugw("UnpackElfChmodExecute detector closed")
	return nil
}

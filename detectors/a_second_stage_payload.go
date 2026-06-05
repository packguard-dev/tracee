package detectors

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/elf"
)

// suspicionWindow matches NonWhitelistedDomainConnection: PIDs stay hot this long.
const suspicionWindow = 5 * time.Minute

type badDomainSuspicionEntry struct {
	domain    string
	expiresAt time.Time
}

var (
	badDomainSuspMu sync.Mutex
	// badDomainSusp tracks PIDs that issued DNS for a non-whitelisted domain.
	badDomainSusp = make(map[uint32]badDomainSuspicionEntry)
)

func markSuspicionAfterNonWhitelistedDNS(pid uint32, domain string) {
	badDomainSuspMu.Lock()
	defer badDomainSuspMu.Unlock()
	badDomainSusp[pid] = badDomainSuspicionEntry{
		domain:    domain,
		expiresAt: time.Now().Add(suspicionWindow),
	}
}

func lookupBadDomainSuspicion(pid uint32) (domain string, ok bool) {
	badDomainSuspMu.Lock()
	defer badDomainSuspMu.Unlock()

	entry, found := badDomainSusp[pid]
	if !found {
		return "", false
	}
	if time.Now().After(entry.expiresAt) {
		delete(badDomainSusp, pid)
		return "", false
	}
	return entry.domain, true
}

func evictExpiredBadDomainSuspicion() {
	badDomainSuspMu.Lock()
	defer badDomainSuspMu.Unlock()
	now := time.Now()
	for pid, e := range badDomainSusp {
		if now.After(e.expiresAt) {
			delete(badDomainSusp, pid)
		}
	}
}

// suspiciousExtensions are file types to watch after a bad-domain DNS hit.
var suspiciousExtensions = map[string]string{
	".py":   "python_script",
	".sh":   "bash_script",
	".bash": "bash_script",
	".dll":  "windows_library",
	".exe":  "windows_executable",
	".js":   "javascript_script",
	".ts":   "typescript_script",
	".ps1":  "powershell_script",
	".rb":   "ruby_script",
	".pl":   "perl_script",
	".elf":  "linux_executable",
}

func init() {
	register(&SecondStagePayloadAfterBadDomain{})
}

// SecondStagePayloadAfterBadDomain fires when a process that recently resolved
// a non-whitelisted domain opens or executes a suspicious file.
type SecondStagePayloadAfterBadDomain struct {
	logger detection.Logger
}

func (d *SecondStagePayloadAfterBadDomain) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-003",

		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "magic_write",
					Dependency: detection.DependencyRequired,
				},
			},
		},

		ProducedEvent: v1beta1.EventDefinition{
			Name:        "second_stage_payload_after_bad_domain",
			Description: "Suspicious file activity after DNS to a non-whitelisted domain",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "domain", Type: "const char*"},
				{Name: "file_path", Type: "const char*"},
				{Name: "file_type", Type: "const char*"},
				{Name: "trigger", Type: "const char*"},
				{Name: "detection_method", Type: "const char*"},
			},
		},

		AutoPopulate: detection.AutoPopulateFields{
			Threat:          false,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *SecondStagePayloadAfterBadDomain) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Infow("SecondStagePayloadAfterBadDomain detector initialized")
	return nil
}

func (d *SecondStagePayloadAfterBadDomain) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	_ = ctx

	switch event.Name {
	case "security_file_open":
		return d.handleFileOpen(event)
	case "sched_process_exec":
		return d.handleExec(event)
	case "magic_write":
		return d.handleMagicWrite(event)
	}
	return nil, nil
}

// End of code that pauses the container

func (d *SecondStagePayloadAfterBadDomain) handleFileOpen(
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return nil, nil
	}

	domain, suspicious := lookupBadDomainSuspicion(pid)
	if !suspicious {
		return nil, nil
	}

	evictExpiredBadDomainSuspicion()

	filePath := extractStringField(event, "pathname")
	if filePath == "" {
		return nil, nil
	}

	fileType, matched := classifySuspiciousFile(filePath)
	if !matched {
		return nil, nil
	}

	d.logger.Infow("Suspicious file opened after non-whitelisted domain DNS",
		"pid", pid, "domain", domain, "path", filePath, "type", fileType)

	go sendPauseSignal(event.GetWorkload().GetContainer().GetId(), "TRC-003", filePath)

	return detection.DetectedWithData(
		[]*v1beta1.EventValue{
			v1beta1.NewStringValue("domain", domain),
			v1beta1.NewStringValue("file_path", filePath),
			v1beta1.NewStringValue("file_type", fileType),
			v1beta1.NewStringValue("trigger", "file_open"),
			v1beta1.NewStringValue("detection_method", "extension"),
		},
	), nil
}

func (d *SecondStagePayloadAfterBadDomain) handleExec(
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return nil, nil
	}

	domain, suspicious := lookupBadDomainSuspicion(pid)
	if !suspicious {
		return nil, nil
	}

	filePath := extractStringField(event, "pathname")
	if filePath == "" {
		filePath = extractStringField(event, "cmdpath")
	}

	fileType, matched := classifySuspiciousFile(filePath)
	detectMethod := ""
	if matched {
		detectMethod = "extension"
	}
	if !matched {
		fileType = "unknown"
	}

	d.logger.Infow("Suspicious exec after non-whitelisted domain DNS",
		"pid", pid, "domain", domain, "path", filePath, "type", fileType)

	go sendPauseSignal(event.GetWorkload().GetContainer().GetId(), "TRC-003", filePath)

	return detection.DetectedWithData(
		[]*v1beta1.EventValue{
			v1beta1.NewStringValue("domain", domain),
			v1beta1.NewStringValue("file_path", filePath),
			v1beta1.NewStringValue("file_type", fileType),
			v1beta1.NewStringValue("trigger", "exec"),
			v1beta1.NewStringValue("detection_method", detectMethod),
		},
	), nil
}

func (d *SecondStagePayloadAfterBadDomain) handleMagicWrite(
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return nil, nil
	}

	domain, suspicious := lookupBadDomainSuspicion(pid)
	if !suspicious {
		return nil, nil
	}

	evictExpiredBadDomainSuspicion()

	header, ok := v1beta1.GetData[[]byte](event, "bytes")
	if !ok || len(header) == 0 {
		return nil, nil
	}

	filePath, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil || filePath == "" {
		return nil, nil
	}

	fileType, matched := classifyByContent(header)
	detectMethod := "content"
	if !matched {
		detectMethod = "extension"
		fileType, matched = classifySuspiciousFile(filePath)
		if !matched {
			return nil, nil
		}
	}

	d.logger.Infow("Suspicious magic write after non-whitelisted domain DNS",
		"pid", pid, "domain", domain, "path", filePath, "type", fileType, "method", detectMethod)

	go sendPauseSignal(event.GetWorkload().GetContainer().GetId(), "TRC-003", filePath)

	return detection.DetectedWithData(
		[]*v1beta1.EventValue{
			v1beta1.NewStringValue("domain", domain),
			v1beta1.NewStringValue("file_path", filePath),
			v1beta1.NewStringValue("file_type", fileType),
			v1beta1.NewStringValue("trigger", "magic_write"),
			v1beta1.NewStringValue("detection_method", detectMethod),
		},
	), nil
}

func classifySuspiciousFile(path string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	fileType, ok := suspiciousExtensions[ext]
	return fileType, ok
}

// parseShebangInterpreter maps the interpreter from a shebang line into a coarse file_type label.
func parseShebangInterpreter(header []byte) (string, bool) {
	if len(header) < 2 {
		return "", false
	}
	if header[0] != '#' || header[1] != '!' {
		return "", false
	}

	idx := bytes.IndexByte(header, '\n')
	var lineBytes []byte
	if idx >= 0 {
		lineBytes = header[2:idx]
	} else {
		lineBytes = header[2:]
	}
	line := strings.TrimSpace(string(lineBytes))
	if line == "" {
		return "", false
	}

	const envPref = "/usr/bin/env "
	if strings.HasPrefix(line, envPref) {
		fields := strings.Fields(line[len(envPref):])
		if len(fields) == 0 {
			return "", false
		}
		line = fields[0]
	} else {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return "", false
		}
		line = fields[0]
	}

	base := filepath.Base(line)
	baseLower := strings.ToLower(strings.TrimSuffix(base, ".exe"))

	switch baseLower {
	case "bash", "sh", "dash", "zsh":
		return "bash_script", true
	case "python", "python2", "python3":
		return "python_script", true
	case "perl":
		return "perl_script", true
	case "ruby":
		return "ruby_script", true
	case "node", "nodejs":
		return "javascript_script", true
	case "pwsh", "powershell":
		return "powershell_script", true
	default:
		return "script", true
	}
}

var (
	machOMagicUniversal = []byte{0xCA, 0xFE, 0xBA, 0xBE}
	machOMagic6432LE    = []byte{0xCF, 0xFA, 0xED, 0xFE}
	peDosMagic          = []byte("MZ")
)

// classifyByContent matches magic bytes or a Unix shebang in the opening bytes.
func classifyByContent(header []byte) (string, bool) {
	if elf.IsElf(header) {
		return "linux_executable", true
	}
	if len(header) >= 2 && bytes.Equal(header[:2], peDosMagic) {
		return "windows_executable", true
	}
	if bytes.HasPrefix(header, machOMagicUniversal) ||
		bytes.HasPrefix(header, machOMagic6432LE) {
		return "macho_executable", true
	}
	return parseShebangInterpreter(header)
}

func extractStringField(event *v1beta1.Event, name string) string {
	for _, data := range event.GetData() {
		if data.GetName() != name {
			continue
		}
		if s := data.GetStr(); s != "" {
			return s
		}
	}
	return ""
}

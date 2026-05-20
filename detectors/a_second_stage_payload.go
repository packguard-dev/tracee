package detectors

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
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
		},
	), nil
}

func classifySuspiciousFile(path string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	fileType, ok := suspiciousExtensions[ext]
	return fileType, ok
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

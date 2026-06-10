package detectors

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	sensitiveReadDNSExfilWindowTTL = 5 * time.Minute
	sensitiveReadDNSExfilMaxPIDs   = 10000
)

type sensitiveReadTaintEntry struct {
	category string
}

type processExecMetadata struct {
	executablePath string
	commandLine    string
	scriptPath     string
	parentPID      uint32
	pwdPath        string
}

func init() {
	register(&SensitiveReadDNSExfiltration{})
}

// SensitiveReadDNSExfiltration correlates sensitive file reads with DNS exfiltration heuristics.
type SensitiveReadDNSExfiltration struct {
	logger detection.Logger

	parentMu      sync.Mutex
	taintByPID    *expirable.LRU[uint32, sensitiveReadTaintEntry]
	execMetaByPID *expirable.LRU[uint32, processExecMetadata]
	parentByPID   map[uint32]uint32
	queryCounts   *expirable.LRU[string, int64]
	whitelist     []string
	windowTTL     time.Duration
	nowFn         func() time.Time
}

func (d *SensitiveReadDNSExfiltration) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-006",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "net_packet_dns_request",
					Dependency: detection.DependencyRequired,
				},
				{
					Name:       "sched_process_exec",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "sensitive_read_dns_exfiltration",
			Description: "Sensitive file read followed by suspicious DNS exfiltration activity",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "query", Type: "const char*"},
				{Name: "base_domain", Type: "const char*"},
				{Name: "subdomain", Type: "const char*"},
				{Name: "heuristic", Type: "const char*"},
				{Name: "metric", Type: "int"},
				{Name: "sensitive_category", Type: "const char*"},
				{Name: "tainted_pid", Type: "unsigned int"},
				{Name: "command_line", Type: "const char*"},
				{Name: "script_path", Type: "const char*"},
				{Name: "executable_path", Type: "const char*"},
				{Name: "pwd_path", Type: "const char*"},
				{Name: "correlation_window_sec", Type: "int"},
				{Name: "correlated", Type: "bool"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "Sensitive Data DNS Exfiltration",
			Description: "Sensitive credential file access followed by suspicious DNS exfiltration pattern",
			Severity:    v1beta1.Severity_CRITICAL,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Exfiltration",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1048/T1071.004",
					Name: "Exfiltration Over Alternative Protocol (DNS)",
				},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *SensitiveReadDNSExfiltration) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.taintByPID = expirable.NewLRU[uint32, sensitiveReadTaintEntry](
		sensitiveReadDNSExfilMaxPIDs,
		nil,
		sensitiveReadDNSExfilWindowTTL,
	)
	d.execMetaByPID = expirable.NewLRU[uint32, processExecMetadata](
		sensitiveReadDNSExfilMaxPIDs,
		nil,
		sensitiveReadDNSExfilWindowTTL,
	)
	d.parentByPID = make(map[uint32]uint32)
	d.queryCounts = expirable.NewLRU[string, int64](
		dnsExfiltrationMaxDomains,
		nil,
		dnsExfiltrationWindowTTL,
	)
	d.windowTTL = sensitiveReadDNSExfilWindowTTL
	d.nowFn = time.Now

	for _, domain := range defaultWhitelist {
		d.whitelist = append(d.whitelist, normalizeDomain(domain))
	}

	d.logger.Infow(
		"SensitiveReadDNSExfiltration detector initialized",
		"window_ttl", d.windowTTL.String(),
		"max_pids", sensitiveReadDNSExfilMaxPIDs,
		"max_domains", dnsExfiltrationMaxDomains,
		"whitelist_size", len(d.whitelist),
	)

	return nil
}

func (d *SensitiveReadDNSExfiltration) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	_ = ctx

	switch event.GetName() {
	case "security_file_open":
		return d.handleSensitiveRead(event), nil
	case "sched_process_exec":
		d.handleExec(event)
		return nil, nil
	case "net_packet_dns_request":
		return d.handleDNS(event), nil
	default:
		return nil, nil
	}
}

func (d *SensitiveReadDNSExfiltration) handleSensitiveRead(event *v1beta1.Event) []detection.DetectorOutput {
	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil || pathname == "" {
		pathname = extractStringField(event, "pathname")
	}
	if pathname == "" || !isDecoyPath(pathname) {
		return nil
	}

	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil || !parsers.IsFileRead(int(flags)) {
		return nil
	}

	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return nil
	}

	parentPID := d.lookupParentPID(pid)
	category := decoyCategory(pathname)
	d.taintByPID.Add(pid, sensitiveReadTaintEntry{category: category})
	if parentPID != 0 {
		d.taintByPID.Add(parentPID, sensitiveReadTaintEntry{category: category})
	}

	return nil
}

func (d *SensitiveReadDNSExfiltration) handleExec(event *v1beta1.Event) {
	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return
	}

	var parentPID uint32
	ppid, err := v1beta1.GetDataSafe[int32](event, "parent_pid")
	if err == nil && ppid > 0 {
		parentPID = uint32(ppid)
	}

	d.parentMu.Lock()
	d.parentByPID[pid] = parentPID
	d.parentMu.Unlock()

	executablePath := extractStringField(event, "pathname")
	if executablePath == "" {
		executablePath = extractStringField(event, "cmdpath")
	}

	argv := extractStringArrayField(event, "argv")
	commandLine := strings.TrimSpace(strings.Join(argv, " "))
	if commandLine == "" {
		commandLine = extractStringField(event, "cmdpath")
	}
	if commandLine == "" {
		commandLine = executablePath
	}

	pwdPath := extractStringField(event, "pwd")

	scriptPath := deriveScriptPath(event, executablePath, argv, pwdPath)

	d.execMetaByPID.Add(pid, processExecMetadata{
		executablePath: executablePath,
		commandLine:    commandLine,
		scriptPath:     scriptPath,
		parentPID:      parentPID,
		pwdPath:        pwdPath,
	})
}

func (d *SensitiveReadDNSExfiltration) handleDNS(event *v1beta1.Event) []detection.DetectorOutput {
	queries := extractDNSQueries(event)
	if len(queries) == 0 {
		return nil
	}

	pid, ok := pidFromEventWorkload(event)
	if !ok {
		return nil
	}

	for _, query := range queries {
		normalizedQuery := normalizeDomain(query.Query)
		subdomain, baseDomain := parseDomainParts(normalizedQuery)
		if shouldRejectDNSQuery(baseDomain, normalizedQuery, d.whitelist) {
			continue
		}

		heuristic, metric, matched := d.matchHeuristic(subdomain, baseDomain)
		if !matched {
			continue
		}

		taintedPID, category, correlated := d.resolveTaint(pid)
		if !correlated {
			continue
		}
		execMeta := d.resolveExecMetadata(pid, taintedPID)

		d.logger.Infow(
			"Sensitive read correlated with DNS exfiltration heuristic",
			"pid", pid,
			"tainted_pid", taintedPID,
			"executable_path", execMeta.executablePath,
			"command_line", execMeta.commandLine,
			"script_path", execMeta.scriptPath,
			"pwd_path", execMeta.pwdPath,
			"query", normalizedQuery,
			"heuristic", heuristic,
			"category", category,
		)

		filePath := execMeta.scriptPath
		if filePath == "" {
			filePath = execMeta.executablePath
		}
		go sendPauseSignal(event.GetWorkload().GetContainer().GetId(), "TRC-006", filePath)

		return detection.DetectedWithData(
			[]*v1beta1.EventValue{
				v1beta1.NewStringValue("query", normalizedQuery),
				v1beta1.NewStringValue("base_domain", baseDomain),
				v1beta1.NewStringValue("subdomain", subdomain),
				v1beta1.NewStringValue("heuristic", heuristic),
				v1beta1.NewInt32Value("metric", metric),
				v1beta1.NewStringValue("sensitive_category", category),
				v1beta1.NewUInt32Value("tainted_pid", taintedPID),
				v1beta1.NewStringValue("command_line", execMeta.commandLine),
				v1beta1.NewStringValue("script_path", execMeta.scriptPath),
				v1beta1.NewStringValue("executable_path", execMeta.executablePath),
				v1beta1.NewStringValue("pwd_path", execMeta.pwdPath),
				v1beta1.NewInt32Value("correlation_window_sec", int32(d.windowTTL.Seconds())),
				v1beta1.NewBoolValue("correlated", true),
			},
		)
	}

	return nil
}

func (d *SensitiveReadDNSExfiltration) matchHeuristic(subdomain, baseDomain string) (string, int32, bool) {
	subdomainLength := len(subdomain)
	if subdomainLength > dnsExfiltrationMaxSubdomainLen {
		return "excessive_subdomain_length", int32(subdomainLength), true
	}

	entropy := calculateEntropy(subdomain)
	if entropy > dnsExfiltrationEntropyCutoff {
		return "high_entropy_payload", int32(math.Round(entropy * 100)), true
	}

	count := d.incrementDomainCount(baseDomain)
	if count > dnsExfiltrationFrequencyCutoff {
		return "high_frequency_burst", int32(count), true
	}

	return "", 0, false
}

func (d *SensitiveReadDNSExfiltration) incrementDomainCount(baseDomain string) int64 {
	count, ok := d.queryCounts.Get(baseDomain)
	if !ok {
		count = 0
	}
	count++
	d.queryCounts.Add(baseDomain, count)
	return count
}

func (d *SensitiveReadDNSExfiltration) resolveTaint(pid uint32) (uint32, string, bool) {
	if taint, ok := d.taintByPID.Get(pid); ok {
		return pid, taint.category, true
	}

	parentPID := d.lookupParentPID(pid)
	if parentPID != 0 {
		if taint, ok := d.taintByPID.Get(parentPID); ok {
			return parentPID, taint.category, true
		}
	}

	return 0, "", false
}

func (d *SensitiveReadDNSExfiltration) lookupParentPID(pid uint32) uint32 {
	d.parentMu.Lock()
	defer d.parentMu.Unlock()
	return d.parentByPID[pid]
}

func (d *SensitiveReadDNSExfiltration) resolveExecMetadata(pid, taintedPID uint32) processExecMetadata {
	if meta, ok := d.execMetaByPID.Get(pid); ok {
		if meta.hasContext() {
			return meta
		}
	}
	if taintedPID != 0 {
		if meta, ok := d.execMetaByPID.Get(taintedPID); ok {
			if meta.hasContext() {
				return meta
			}
		}
	}
	parentPID := d.lookupParentPID(pid)
	if parentPID != 0 {
		if meta, ok := d.execMetaByPID.Get(parentPID); ok {
			if meta.hasContext() {
				return meta
			}
		}
	}
	return processExecMetadata{}
}

func (m processExecMetadata) hasContext() bool {
	return m.executablePath != "" || m.commandLine != "" || m.scriptPath != ""
}

func extractStringArrayField(event *v1beta1.Event, name string) []string {
	for _, data := range event.GetData() {
		if data.GetName() != name {
			continue
		}
		if strArrayVal, ok := data.GetValue().(*v1beta1.EventValue_StrArray); ok {
			if strArrayVal.StrArray != nil {
				return strArrayVal.StrArray.GetValue()
			}
		}
	}
	return nil
}

func deriveScriptPath(event *v1beta1.Event, executablePath string, argv []string, pwdPath string) string {
	if len(argv) < 2 {
		return ""
	}
	interpreterPath := extractStringField(event, "interpreter_pathname")
	interpreter := extractStringField(event, "interp")

	if looksLikeInterpreter(executablePath) || looksLikeInterpreter(interpreterPath) || looksLikeInterpreter(interpreter) {
		for _, arg := range argv[1:] {
			if arg == "" || strings.HasPrefix(arg, "-") {
				continue
			}
			if strings.HasPrefix(arg, "/") || strings.Contains(arg, "/") || strings.HasSuffix(strings.ToLower(arg), ".py") ||
				strings.HasSuffix(strings.ToLower(arg), ".sh") || strings.HasSuffix(strings.ToLower(arg), ".pl") ||
				strings.HasSuffix(strings.ToLower(arg), ".rb") || strings.HasSuffix(strings.ToLower(arg), ".js") {
				return resolveAbsoluteScriptPath(arg, pwdPath)
			}
		}
	}
	return ""
}

// resolveAbsoluteScriptPath joins a relative script argument with pwd from sched_process_exec.
func resolveAbsoluteScriptPath(scriptPath, pwdPath string) string {
	if scriptPath == "" {
		return ""
	}
	if filepath.IsAbs(scriptPath) {
		return filepath.Clean(scriptPath)
	}
	if pwdPath == "" {
		return scriptPath
	}
	return filepath.Clean(filepath.Join(pwdPath, scriptPath))
}

func looksLikeInterpreter(path string) bool {
	if path == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "python", "python2", "python3", "python3.10", "python3.11", "bash", "sh", "dash", "zsh", "ksh",
		"perl", "node", "nodejs", "ruby", "php", "lua", "pwsh", "powershell", "deno":
		return true
	default:
		return strings.HasPrefix(base, "python")
	}
}

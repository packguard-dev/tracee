package model

import "time"

const (
	FileOpRead   = "READ"
	FileOpWrite  = "WRITE"
	FileOpDelete = "DELETE"
	FileOpRename = "RENAME"
)

var (
	ProcessLifecycleEvents = map[string]struct{}{
		"sched_process_fork": {},
		"sched_process_exec": {},
		"sched_process_exit": {},
	}

	FileActivityEvents = map[string]struct{}{
		"security_file_open":    {},
		"security_inode_rename": {},
		"file_modification":     {},
		"security_inode_unlink": {},
	}

	DefaultIOCEvents = map[string]struct{}{
		"decoy_file_read":                  {},
		"non_whitelisted_domain_connection": {},
		"dns_exfiltration":                 {},
		"sensitive_read_dns_exfiltration":  {},
		"fileless_execution":               {},
		"hidden_file_created":              {},
	}
)

// NormalizedEvent is the internal representation after JSON ingestion.
type NormalizedEvent struct {
	Index          int
	Timestamp      time.Time
	EventName      string
	ProcessKey     string
	ParentKey      string
	PID            uint32
	HostPID        uint32
	ParentPID      uint32
	ProcessName    string
	ExecutablePath string
	ContainerID    string
	AncestorKeys   []string
	Fields         map[string]any
	DetectedFrom   *DetectedFromEvent
	IsIOC          bool
}

type DetectedFromEvent struct {
	ID   uint32
	Name string
	Data map[string]any
}

type ProcessNode struct {
	Key            string            `json:"key"`
	PID            uint32            `json:"pid,omitempty"`
	HostPID        uint32            `json:"host_pid,omitempty"`
	ParentKey      string            `json:"parent_key,omitempty"`
	ProcessName    string            `json:"process_name,omitempty"`
	ExecutablePath string            `json:"executable_path,omitempty"`
	Argv           []string          `json:"argv,omitempty"`
	CommandLine    string            `json:"command_line,omitempty"`
	Pwd            string            `json:"pwd,omitempty"`
	ForkTime       *time.Time        `json:"fork_time,omitempty"`
	ExecTime       *time.Time        `json:"exec_time,omitempty"`
	ExitTime       *time.Time        `json:"exit_time,omitempty"`
	ExitCode       *int32            `json:"exit_code,omitempty"`
	SignalCode     *int32            `json:"signal_code,omitempty"`
	ContainerID    string            `json:"container_id,omitempty"`
	AncestorKeys   []string          `json:"ancestor_keys,omitempty"`
	IOCIDs         []string          `json:"ioc_ids,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type FileRecord struct {
	ID         string            `json:"id"`
	Operation  string            `json:"operation"`
	Path       string            `json:"path"`
	OldPath    string            `json:"old_path,omitempty"`
	NewPath    string            `json:"new_path,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
	ProcessKey string            `json:"process_key"`
	EventName  string            `json:"event_name"`
	Flags      string            `json:"flags,omitempty"`
	Dev        uint32            `json:"dev,omitempty"`
	Inode      uint64            `json:"inode,omitempty"`
	IOCIDs     []string          `json:"ioc_ids,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type FileGroups struct {
	Read   []FileRecord `json:"READ"`
	Write  []FileRecord `json:"WRITE"`
	Delete []FileRecord `json:"DELETE"`
	Rename []FileRecord `json:"RENAME"`
}

type IOCRecord struct {
	ID                 string            `json:"id"`
	Timestamp          time.Time         `json:"timestamp"`
	EventName          string            `json:"event_name"`
	ProcessKey         string            `json:"process_key"`
	Fields             map[string]any    `json:"fields,omitempty"`
	DetectedFrom       *DetectedFromEvent `json:"detected_from,omitempty"`
	RelatedProcessKeys []string          `json:"related_process_keys,omitempty"`
	RelatedFileIDs     []string          `json:"related_file_ids,omitempty"`
	Relations          []IOCRelation     `json:"relations,omitempty"`
}

type IOCRelation struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

type ProcessTree struct {
	Nodes map[string]ProcessNode `json:"nodes"`
	Roots []string              `json:"roots"`
}

type Output struct {
	Meta         OutputMeta  `json:"meta"`
	ProcessTree  ProcessTree `json:"process_tree"`
	Files        FileGroups  `json:"files"`
	IOCs         []IOCRecord `json:"iocs"`
}

type OutputMeta struct {
	GeneratedAt          time.Time `json:"generated_at"`
	InputEvents          int       `json:"input_events"`
	CorrelationWindowSec int       `json:"correlation_window_sec"`
}

type BuildOptions struct {
	CorrelationWindow time.Duration
	IOCEvents         map[string]struct{}
	Workers           int // 0 uses GOMAXPROCS
}

func DefaultBuildOptions() BuildOptions {
	return BuildOptions{
		CorrelationWindow: 5 * time.Minute,
		IOCEvents:         copyEventSet(DefaultIOCEvents),
	}
}

func copyEventSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

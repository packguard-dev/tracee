package model

import (
	"fmt"
	"time"
)

const (
	FileOpRead     = "READ"
	FileOpWrite    = "WRITE"
	FileOpDelete   = "DELETE"
	FileOpRename   = "RENAME"
	NetworkOpConnect = "CONNECT"
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

	NetworkActivityEvents = map[string]struct{}{
		"net_tcp_connect": {},
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
	ContainerID    string            `json:"-"`
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
	Flags         string            `json:"flags,omitempty"`
	ContainerID   string            `json:"container_id,omitempty"`
	Dev           uint32            `json:"dev,omitempty"`
	Inode         uint64            `json:"inode,omitempty"`
	Ctime         uint64            `json:"ctime,omitempty"`
	IOCIDs        []string          `json:"ioc_ids,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type FileGroups struct {
	Read   []FileRecord `json:"READ"`
	Write  []FileRecord `json:"WRITE"`
	Delete []FileRecord `json:"DELETE"`
	Rename []FileRecord `json:"RENAME"`
}

type NetworkRecord struct {
	ID         string            `json:"id"`
	Operation  string            `json:"operation"`
	Dst        string            `json:"dst"`
	DstPort    int32             `json:"dst_port,omitempty"`
	DstDNS     []string          `json:"dst_dns,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
	ProcessKey string            `json:"process_key"`
	EventName  string            `json:"event_name"`
	IOCIDs     []string          `json:"ioc_ids,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type NetworkGroups struct {
	Connect []NetworkRecord `json:"CONNECT"`
}

type FileIdentityRef struct {
	Inode  uint64 `json:"inode"`
	Ctime  uint64 `json:"ctime"`
	Source string `json:"source,omitempty"`
}

type PayloadInfo struct {
	Path         string `json:"path,omitempty"`
	Inode        uint64 `json:"inode,omitempty"`
	Ctime        uint64 `json:"ctime,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	ArtifactPath string `json:"artifact_path,omitempty"`
	Status       string `json:"status,omitempty"`
	FileCategory string `json:"file_category,omitempty"`
	FileType     string `json:"file_type,omitempty"`
}

type ExternalIndicator struct {
	IP       string `json:"ip"`
	Port     int32  `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Domain   string `json:"domain,omitempty"`
}

type PcapEnrichment struct {
	Source     string              `json:"source"`
	WindowSec  int                 `json:"window_sec"`
	MatchMode  string              `json:"match_mode"`
	Indicators []ExternalIndicator `json:"indicators"`
}

const (
	PcapMatchModeHints  = "hints"
	PcapMatchModeWindow = "window"
)

type MitmRequest struct {
	Timestamp     time.Time `json:"timestamp"`
	Host          string    `json:"host"`
	Port          int32     `json:"port,omitempty"`
	Scheme        string    `json:"scheme,omitempty"`
	URL           string    `json:"url"`
	Method        string    `json:"method,omitempty"`
	SNI           string    `json:"sni,omitempty"`
	ResponseBytes int64     `json:"response_bytes"`
}

type MitmEnrichment struct {
	Source    string        `json:"source"`
	WindowSec int           `json:"window_sec"`
	MatchMode string        `json:"match_mode"`
	Requests  []MitmRequest `json:"requests"`
}

const (
	PayloadStatusFound       = "found"
	PayloadStatusNotInEvents = "not_in_events"
	PayloadStatusNotInZip    = "not_in_zip"
	PayloadStatusNoPath      = "no_path"

	PayloadCategoryExecutable = "executable"
	PayloadCategoryScript     = "script"

	PayloadTypeELF        = "ELF"
	PayloadTypePE         = "PE"
	PayloadTypeDLL        = "DLL"
	PayloadTypeBinary     = "binary"
	PayloadTypePython     = "Python"
	PayloadTypeJavaScript = "JavaScript"
	PayloadTypeBash       = "Bash"
)

type IOCRecord struct {
	ID                 string            `json:"id"`
	Timestamp          time.Time         `json:"timestamp"`
	EventName          string            `json:"event_name"`
	ProcessKey         string            `json:"process_key"`
	Fields             map[string]any    `json:"fields,omitempty"`
	DetectedFrom       *DetectedFromEvent `json:"detected_from,omitempty"`
	RelatedProcessKeys  []string          `json:"related_process_keys,omitempty"`
	RelatedFileIDs      []string          `json:"related_file_ids,omitempty"`
	RelatedNetworkIDs   []string          `json:"related_network_ids,omitempty"`
	Relations           []IOCRelation     `json:"relations,omitempty"`
	Payload            *PayloadInfo      `json:"payload,omitempty"`
	Pcap               *PcapEnrichment   `json:"pcap,omitempty"`
	Mitm               *MitmEnrichment   `json:"mitm,omitempty"`
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
	Meta         OutputMeta                 `json:"meta"`
	ProcessTree  ProcessTree                `json:"process_tree"`
	Files        FileGroups                 `json:"files"`
	Networks     NetworkGroups              `json:"networks"`
	IOCs         []IOCRecord                `json:"iocs"`
	PathFileIdentity map[string][]FileIdentityRef `json:"-"`
}

// NormalizeContainerID maps an empty container ID to "host".
func NormalizeContainerID(containerID string) string {
	if containerID == "" {
		return "host"
	}
	return containerID
}

// FileIdentityKey returns the canonical file identity key for inode and ctime.
func FileIdentityKey(inode, ctime uint64) string {
	return fmt.Sprintf("%d:%d", inode, ctime)
}

type OutputMeta struct {
	GeneratedAt          time.Time `json:"generated_at"`
	InputEvents          int       `json:"input_events"`
	CorrelationWindowSec int       `json:"correlation_window_sec"`
	PcapSource           string    `json:"pcap_source,omitempty"`
	MitmSource           string    `json:"mitm_source,omitempty"`
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

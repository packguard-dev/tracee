package detectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func TestSensitiveReadDNSExfiltration_OnEvent(t *testing.T) {
	t.Parallel()

	d := &SensitiveReadDNSExfiltration{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	t.Run("ignore unrelated event", func(t *testing.T) {
		out, err := d.OnEvent(context.Background(), &v1beta1.Event{Name: "sched_switch"})
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("do not taint on non-sensitive read path", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(11001, "/tmp/normal.txt", 0))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(11001, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("dns heuristic without taint has no alert", func(t *testing.T) {
		out, err := d.OnEvent(context.Background(), dnsEventWithPID(12001, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("detect with pid taint", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(13001, "/root/.env", 0))
		require.NoError(t, err)
		_, err = d.OnEvent(context.Background(), execEventWithMeta(13001, 13000, "/usr/bin/python3.10", []string{
			"python3",
			"/tmp/_payload.py",
			"--domain",
			"attacker.com",
		}, "/usr/bin/python3.10", "python3", ""))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(13001, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, "high_entropy_payload", eventValueAsStringData(t, out[0].Data, "heuristic"))
		assert.Equal(t, "env_file", eventValueAsStringData(t, out[0].Data, "sensitive_category"))
		assert.Equal(t, uint32(13001), eventValueAsUInt32(t, out[0].Data, "tainted_pid"))
		assert.Equal(t, "/usr/bin/python3.10", eventValueAsStringData(t, out[0].Data, "executable_path"))
		assert.Equal(t, "/tmp/_payload.py", eventValueAsStringData(t, out[0].Data, "script_path"))
		assert.Equal(t, "python3 /tmp/_payload.py --domain attacker.com", eventValueAsStringData(t, out[0].Data, "command_line"))
		assert.Equal(t, int32(300), eventValueAsInt32(t, out[0].Data, "correlation_window_sec"))
	})

	t.Run("detect with parent pid taint from exec map and own metadata", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(14001, "/root/.env", 0))
		require.NoError(t, err)

		_, err = d.OnEvent(context.Background(), execEventWithMeta(14002, 14001, "/usr/bin/node", []string{
			"node",
			"/tmp/stealer.js",
		}, "/usr/bin/node", "node", ""))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(14002, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, uint32(14001), eventValueAsUInt32(t, out[0].Data, "tainted_pid"))
		assert.Equal(t, "env_file", eventValueAsStringData(t, out[0].Data, "sensitive_category"))
		assert.Equal(t, "/usr/bin/node", eventValueAsStringData(t, out[0].Data, "executable_path"))
		assert.Equal(t, "/tmp/stealer.js", eventValueAsStringData(t, out[0].Data, "script_path"))
	})

	t.Run("metadata fallback uses tainted pid when dns pid metadata missing", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(17001, "/root/.env", 0))
		require.NoError(t, err)
		_, err = d.OnEvent(context.Background(), execEventWithMeta(17001, 17000, "/usr/bin/bash", []string{
			"bash",
			"/tmp/exfil.sh",
		}, "/usr/bin/bash", "bash", ""))
		require.NoError(t, err)

		_, err = d.OnEvent(context.Background(), execEvent(17002, 17001))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(17002, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, uint32(17001), eventValueAsUInt32(t, out[0].Data, "tainted_pid"))
		assert.Equal(t, "/usr/bin/bash", eventValueAsStringData(t, out[0].Data, "executable_path"))
		assert.Equal(t, "/tmp/exfil.sh", eventValueAsStringData(t, out[0].Data, "script_path"))
		assert.Equal(t, "bash /tmp/exfil.sh", eventValueAsStringData(t, out[0].Data, "command_line"))
	})

	t.Run("metadata fallback uses parent pid when dns and tainted pid metadata missing", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(18002, "/root/.env", 0))
		require.NoError(t, err)
		_, err = d.OnEvent(context.Background(), execEventWithMeta(18001, 18000, "/usr/bin/python3.10", []string{
			"python3",
			"/tmp/parent_payload.py",
		}, "/usr/bin/python3.10", "python3", ""))
		require.NoError(t, err)
		_, err = d.OnEvent(context.Background(), execEvent(18002, 18001))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(18002, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, uint32(18002), eventValueAsUInt32(t, out[0].Data, "tainted_pid"))
		assert.Equal(t, "/usr/bin/python3.10", eventValueAsStringData(t, out[0].Data, "executable_path"))
		assert.Equal(t, "/tmp/parent_payload.py", eventValueAsStringData(t, out[0].Data, "script_path"))
	})

	t.Run("resolve relative script path with pwd", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(20001, "/root/.env", 0))
		require.NoError(t, err)
		_, err = d.OnEvent(context.Background(), execEventWithMeta(20001, 20000, "/usr/bin/python3.10", []string{
			"python3",
			"payload.py",
		}, "/usr/bin/python3.10", "python3", "/app"))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(20001, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, "/app", eventValueAsStringData(t, out[0].Data, "pwd_path"))
		assert.Equal(t, "/app/payload.py", eventValueAsStringData(t, out[0].Data, "script_path"))
		assert.Equal(t, "python3 payload.py", eventValueAsStringData(t, out[0].Data, "command_line"))
	})

	t.Run("detect when exec metadata fields are partially missing", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(19001, "/root/.env", 0))
		require.NoError(t, err)
		_, err = d.OnEvent(context.Background(), execEvent(19001, 19000))
		require.NoError(t, err)

		out, err := d.OnEvent(context.Background(), dnsEventWithPID(19001, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, uint32(19001), eventValueAsUInt32(t, out[0].Data, "tainted_pid"))
		assert.Equal(t, "", eventValueAsStringData(t, out[0].Data, "executable_path"))
		assert.Equal(t, "", eventValueAsStringData(t, out[0].Data, "script_path"))
		assert.Equal(t, "", eventValueAsStringData(t, out[0].Data, "command_line"))
	})

	t.Run("taint expires after five minute window", func(t *testing.T) {
		d.taintByPID = expirable.NewLRU[uint32, sensitiveReadTaintEntry](
			sensitiveReadDNSExfilMaxPIDs,
			nil,
			20*time.Millisecond,
		)

		_, err := d.OnEvent(context.Background(), securityOpenEvent(15001, "/root/.env", 0))
		require.NoError(t, err)

		time.Sleep(40 * time.Millisecond)
		out, err := d.OnEvent(context.Background(), dnsEventWithPID(15001, "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"))
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("detect excessive subdomain heuristic when tainted", func(t *testing.T) {
		_, err := d.OnEvent(context.Background(), securityOpenEvent(16001, "/root/.bash_history", 0))
		require.NoError(t, err)

		longSubdomain := strings.Repeat("x", dnsExfiltrationMaxSubdomainLen+1) + ".attacker.com"
		out, err := d.OnEvent(context.Background(), dnsEventWithPID(16001, longSubdomain))
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, "excessive_subdomain_length", eventValueAsStringData(t, out[0].Data, "heuristic"))
		assert.Equal(t, "shell_history", eventValueAsStringData(t, out[0].Data, "sensitive_category"))
	})
}

func securityOpenEvent(pid uint32, path string, flags int32) *v1beta1.Event {
	return &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewInt32Value("flags", flags),
		},
	}
}

func dnsEventWithPID(pid uint32, query string) *v1beta1.Event {
	return &v1beta1.Event{
		Name: "net_packet_dns_request",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			{
				Name: "dns_questions",
				Value: &v1beta1.EventValue_DnsQuestions{
					DnsQuestions: &v1beta1.DnsQuestions{
						Questions: []*v1beta1.DnsQueryData{
							{Query: query},
						},
					},
				},
			},
		},
	}
}

func execEvent(pid uint32, ppid int32) *v1beta1.Event {
	return &v1beta1.Event{
		Name: "sched_process_exec",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("parent_pid", ppid),
		},
	}
}

func execEventWithMeta(
	pid uint32,
	ppid int32,
	pathname string,
	argv []string,
	interpreterPath string,
	interpreter string,
	pwd string,
) *v1beta1.Event {
	data := []*v1beta1.EventValue{
		v1beta1.NewInt32Value("parent_pid", ppid),
		v1beta1.NewStringValue("pathname", pathname),
	}
	if len(argv) > 0 {
		data = append(data, &v1beta1.EventValue{
			Name: "argv",
			Value: &v1beta1.EventValue_StrArray{
				StrArray: &v1beta1.StringArray{Value: argv},
			},
		})
	}
	if interpreterPath != "" {
		data = append(data, v1beta1.NewStringValue("interpreter_pathname", interpreterPath))
	}
	if interpreter != "" {
		data = append(data, v1beta1.NewStringValue("interp", interpreter))
	}
	if pwd != "" {
		data = append(data, v1beta1.NewStringValue("pwd", pwd))
	}

	return &v1beta1.Event{
		Name: "sched_process_exec",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: data,
	}
}

func eventValueAsInt32(t *testing.T, data []*v1beta1.EventValue, name string) int32 {
	t.Helper()
	for _, item := range data {
		if item.GetName() == name {
			return item.GetInt32()
		}
	}
	t.Fatalf("missing event data value %q", name)
	return 0
}

func eventValueAsUInt32(t *testing.T, data []*v1beta1.EventValue, name string) uint32 {
	t.Helper()
	for _, item := range data {
		if item.GetName() == name {
			return item.GetUInt32()
		}
	}
	t.Fatalf("missing event data value %q", name)
	return 0
}

func eventValueAsStringData(t *testing.T, data []*v1beta1.EventValue, name string) string {
	t.Helper()
	for _, item := range data {
		if item.GetName() == name {
			return item.GetStr()
		}
	}
	t.Fatalf("missing event data value %q", name)
	return ""
}


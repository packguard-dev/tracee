package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func clearBadDomainSuspicion(t *testing.T, pid uint32) {
	t.Helper()
	badDomainSuspMu.Lock()
	delete(badDomainSusp, pid)
	badDomainSuspMu.Unlock()
}

func TestSecondStagePayloadAfterBadDomain_fileOpen(t *testing.T) {
	t.Parallel()

	const pid uint32 = 90001
	t.Cleanup(func() { clearBadDomainSuspicion(t, pid) })

	markSuspicionAfterNonWhitelistedDNS(pid, "evil.com")

	d := &SecondStagePayloadAfterBadDomain{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/payload.py"),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "domain", out[0].Data[0].GetName())
	assert.Equal(t, "evil.com", out[0].Data[0].GetStr())
	assert.Equal(t, "file_path", out[0].Data[1].GetName())
	assert.Equal(t, "/tmp/payload.py", out[0].Data[1].GetStr())
	assert.Equal(t, "file_type", out[0].Data[2].GetName())
	assert.Equal(t, "python_script", out[0].Data[2].GetStr())
	assert.Equal(t, "trigger", out[0].Data[3].GetName())
	assert.Equal(t, "file_open", out[0].Data[3].GetStr())
}

func TestSecondStagePayloadAfterBadDomain_noMarkNoDetect(t *testing.T) {
	t.Parallel()

	d := &SecondStagePayloadAfterBadDomain{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(90002),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/payload.py"),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestSecondStagePayloadAfterBadDomain_execUnknownExt(t *testing.T) {
	t.Parallel()

	const pid uint32 = 90003
	t.Cleanup(func() { clearBadDomainSuspicion(t, pid) })

	markSuspicionAfterNonWhitelistedDNS(pid, "evil.com")

	d := &SecondStagePayloadAfterBadDomain{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "sched_process_exec",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/usr/bin/mystery.bin"),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "unknown", out[0].Data[2].GetStr())
	assert.Equal(t, "exec", out[0].Data[3].GetStr())
}

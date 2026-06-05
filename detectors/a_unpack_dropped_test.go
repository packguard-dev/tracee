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

func elfMagicPrefix() []byte {
	return []byte{0x7f, 'E', 'L', 'F'}
}

func clearUnpackElfChmodPID(t *testing.T, pid uint32) {
	t.Helper()
	t.Cleanup(func() {
		unpackElfChmodMu.Lock()
		delete(unpackElfChmod, pid)
		unpackElfChmodMu.Unlock()
	})
}

func workload(pid uint32) *v1beta1.Workload {
	return &v1beta1.Workload{
		Process: &v1beta1.Process{
			Pid: wrapperspb.UInt32(pid),
		},
		Container: &v1beta1.Container{
			Id: "test-c",
		},
	}
}

func TestUnpackElfChmodExecute_Definition(t *testing.T) {
	t.Parallel()

	d := &UnpackElfChmodExecute{}
	def := d.GetDefinition()

	assert.Equal(t, "TRC-005", def.ID)
	assert.Equal(t, "unpack_elf_chmod_execute", def.ProducedEvent.Name)
	require.NotNil(t, def.ThreatMetadata)
	assert.Equal(t, "T1140", def.ThreatMetadata.Mitre.Technique.Id)

	names := make([]string, len(def.Requirements.Events))
	for i, e := range def.Requirements.Events {
		names[i] = e.Name
	}
	assert.Contains(t, names, "magic_write")
	assert.Contains(t, names, "chmod")
	assert.Contains(t, names, "fchmodat")
	assert.Contains(t, names, "chmod_common")
	assert.Contains(t, names, "fchmod")
	assert.Contains(t, names, "sched_process_exec")
}

func TestUnpackElfChmodExecute_fullChain(t *testing.T) {
	t.Parallel()

	const pid uint32 = 92001
	clearUnpackElfChmodPID(t, pid)

	d := &UnpackElfChmodExecute{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	path := "/tmp/stage2.bin"
	w := workload(pid)

	_, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "magic_write",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewBytesValue("bytes", elfMagicPrefix()),
		},
	})
	require.NoError(t, err)

	_, err = d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "chmod",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewUInt32Value("mode", 0o755),
			v1beta1.NewInt64Value("returnValue", 0),
		},
	})
	require.NoError(t, err)

	out, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "sched_process_exec",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
		},
	})
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, path, testutil.GetOutputData(out[0], "file_path"))
	assert.Equal(t, "sched_process_exec", testutil.GetOutputData(out[0], "trigger"))
}

func TestUnpackElfChmodExecute_noChmodNoDetect(t *testing.T) {
	t.Parallel()

	const pid uint32 = 92002
	clearUnpackElfChmodPID(t, pid)

	d := &UnpackElfChmodExecute{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	path := "/tmp/nochmod.bin"
	w := workload(pid)

	_, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "magic_write",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewBytesValue("bytes", elfMagicPrefix()),
		},
	})
	require.NoError(t, err)

	out, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "sched_process_exec",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
		},
	})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestUnpackElfChmodExecute_chmodWithoutExecBits(t *testing.T) {
	t.Parallel()

	const pid uint32 = 92003
	clearUnpackElfChmodPID(t, pid)

	d := &UnpackElfChmodExecute{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	path := "/tmp/0644.bin"
	w := workload(pid)

	_, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "magic_write",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewBytesValue("bytes", elfMagicPrefix()),
		},
	})
	require.NoError(t, err)

	_, err = d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "chmod",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewUInt32Value("mode", 0o644),
			v1beta1.NewInt64Value("returnValue", 0),
		},
	})
	require.NoError(t, err)

	out, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "sched_process_exec",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
		},
	})
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestUnpackElfChmodExecute_fchmodSinglePendingPath(t *testing.T) {
	t.Parallel()

	const pid uint32 = 92004
	clearUnpackElfChmodPID(t, pid)

	d := &UnpackElfChmodExecute{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	path := "/tmp/fchmod-one.bin"
	w := workload(pid)

	_, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "magic_write",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
			v1beta1.NewBytesValue("bytes", elfMagicPrefix()),
		},
	})
	require.NoError(t, err)

	_, err = d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "fchmod",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewInt32Value("fd", 3),
			v1beta1.NewUInt32Value("mode", 0o755),
			v1beta1.NewInt64Value("returnValue", 0),
		},
	})
	require.NoError(t, err)

	out, err := d.OnEvent(context.Background(), &v1beta1.Event{
		Name:     "sched_process_exec",
		Workload: w,
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", path),
		},
	})
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, path, testutil.GetOutputData(out[0], "file_path"))
}

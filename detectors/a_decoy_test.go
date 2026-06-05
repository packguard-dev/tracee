package detectors

import (
	"context"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestDecoyFileRead_detect(t *testing.T) {
	t.Parallel()

	d := &DecoyFileRead{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(91001),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/root/.aws/credentials"),
			v1beta1.NewInt32Value("flags", int32(syscall.O_RDONLY)),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "file_path", out[0].Data[0].GetName())
	assert.Equal(t, "/root/.aws/credentials", out[0].Data[0].GetStr())
	assert.Equal(t, "decoy_category", out[0].Data[1].GetName())
	assert.Equal(t, "cloud_creds", out[0].Data[1].GetStr())
}

func TestDecoyFileRead_prefix(t *testing.T) {
	t.Parallel()

	d := &DecoyFileRead{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(91002),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/root/.ssh/id_rsa"),
			v1beta1.NewInt32Value("flags", 0),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "/root/.ssh/id_rsa", out[0].Data[0].GetStr())
	assert.Equal(t, "ssh", out[0].Data[1].GetStr())
}

func TestDecoyFileRead_k8sSA(t *testing.T) {
	t.Parallel()

	d := &DecoyFileRead{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(91003),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
			v1beta1.NewInt32Value("flags", int32(syscall.O_RDWR)),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "kube", out[0].Data[1].GetStr())
}

func TestDecoyFileRead_nonDecoy(t *testing.T) {
	t.Parallel()

	d := &DecoyFileRead{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(91004),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/etc/passwd"),
			v1beta1.NewInt32Value("flags", int32(syscall.O_RDONLY)),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestDecoyFileRead_writeOnly(t *testing.T) {
	t.Parallel()

	d := &DecoyFileRead{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	evt := &v1beta1.Event{
		Name: "security_file_open",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(91005),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/root/.aws/credentials"),
			v1beta1.NewInt32Value("flags", int32(syscall.O_WRONLY)),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	assert.Empty(t, out)
}

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
	assert.Equal(t, "detection_method", out[0].Data[4].GetName())
	assert.Equal(t, "extension", out[0].Data[4].GetStr())
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

func TestSecondStagePayloadAfterBadDomain_execKnownExt(t *testing.T) {
	t.Parallel()

	const pid uint32 = 90008
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
			v1beta1.NewStringValue("pathname", "/usr/local/bin/script.py"),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "python_script", out[0].Data[2].GetStr())
	assert.Equal(t, "exec", out[0].Data[3].GetStr())
	assert.Equal(t, "extension", out[0].Data[4].GetStr())
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
	assert.Equal(t, "detection_method", out[0].Data[4].GetName())
	assert.Equal(t, "", out[0].Data[4].GetStr())
}

func TestClassifyByContent(t *testing.T) {
	t.Parallel()

	elfHdr := []byte{0x7F, 'E', 'L', 'F'}

	tests := []struct {
		name       string
		header     []byte
		wantType   string
		wantMatch  bool
	}{
		{
			name:      "ELF",
			header:    elfHdr,
			wantType:  "linux_executable",
			wantMatch: true,
		},
		{
			name:      "PE MZ",
			header:    []byte{'M', 'Z', 0, 0},
			wantType:  "windows_executable",
			wantMatch: true,
		},
		{
			name:      "Mach-O universal",
			header:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0},
			wantType:  "macho_executable",
			wantMatch: true,
		},
		{
			name:      "Mach-O 64 LE",
			header:    []byte{0xCF, 0xFA, 0xED, 0xFE},
			wantType:  "macho_executable",
			wantMatch: true,
		},
		{
			name:      "shebang python3",
			header:    []byte("#!/usr/bin/python3\n"),
			wantType:  "python_script",
			wantMatch: true,
		},
		{
			name:      "shebang env python3",
			header:    []byte("#!/usr/bin/env python3\n"),
			wantType:  "python_script",
			wantMatch: true,
		},
		{
			name:      "shebang bash",
			header:    []byte("#!/bin/bash\n"),
			wantType:  "bash_script",
			wantMatch: true,
		},
		{
			name:      "shebang unknown interpreter",
			header:    []byte("#!/opt/foo/bar\n"),
			wantType:  "script",
			wantMatch: true,
		},
		{
			name:      "no match",
			header:    []byte("plain text"),
			wantType:  "",
			wantMatch: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotType, gotOK := classifyByContent(tc.header)
			assert.Equal(t, tc.wantMatch, gotOK)
			assert.Equal(t, tc.wantType, gotType)
		})
	}
}

func TestSecondStagePayloadAfterBadDomain_magicWriteContentELF(t *testing.T) {
	t.Parallel()

	const pid uint32 = 90004
	t.Cleanup(func() { clearBadDomainSuspicion(t, pid) })
	markSuspicionAfterNonWhitelistedDNS(pid, "evil.net")

	d := &SecondStagePayloadAfterBadDomain{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	evt := &v1beta1.Event{
		Name: "magic_write",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/runner.xyz"),
			v1beta1.NewBytesValue("bytes", []byte{0x7F, 'E', 'L', 'F'}),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "/tmp/runner.xyz", out[0].Data[1].GetStr())
	assert.Equal(t, "linux_executable", out[0].Data[2].GetStr())
	assert.Equal(t, "magic_write", out[0].Data[3].GetStr())
	assert.Equal(t, "content", out[0].Data[4].GetStr())
}

func TestSecondStagePayloadAfterBadDomain_magicWriteExtensionFallback(t *testing.T) {
	t.Parallel()

	const pid uint32 = 90005
	t.Cleanup(func() { clearBadDomainSuspicion(t, pid) })
	markSuspicionAfterNonWhitelistedDNS(pid, "evil.net")

	d := &SecondStagePayloadAfterBadDomain{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	evt := &v1beta1.Event{
		Name: "magic_write",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/hide.py"),
			v1beta1.NewBytesValue("bytes", []byte("not-a-shebang")),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "python_script", out[0].Data[2].GetStr())
	assert.Equal(t, "magic_write", out[0].Data[3].GetStr())
	assert.Equal(t, "extension", out[0].Data[4].GetStr())
}

func TestSecondStagePayloadAfterBadDomain_magicWriteNoSuspicionNoDetect(t *testing.T) {
	t.Parallel()

	d := &SecondStagePayloadAfterBadDomain{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	evt := &v1beta1.Event{
		Name: "magic_write",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(90006),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/foo.py"),
			v1beta1.NewBytesValue("bytes", []byte{0x7F, 'E', 'L', 'F'}),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestSecondStagePayloadAfterBadDomain_magicWriteNoMatch(t *testing.T) {
	t.Parallel()

	const pid uint32 = 90007
	t.Cleanup(func() { clearBadDomainSuspicion(t, pid) })
	markSuspicionAfterNonWhitelistedDNS(pid, "evil.net")

	d := &SecondStagePayloadAfterBadDomain{}
	require.NoError(t, d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}}))

	evt := &v1beta1.Event{
		Name: "magic_write",
		Workload: &v1beta1.Workload{
			Process: &v1beta1.Process{
				Pid: wrapperspb.UInt32(pid),
			},
		},
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("pathname", "/tmp/plain.txt"),
			v1beta1.NewBytesValue("bytes", []byte("hello")),
		},
	}

	out, err := d.OnEvent(context.Background(), evt)
	require.NoError(t, err)
	assert.Empty(t, out)
}

package build

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestEnrichPayloadsWithArtifacts(t *testing.T) {
	t.Parallel()

	events := []model.NormalizedEvent{
		{
			Index:          1,
			Timestamp:      time.Now(),
			EventName:      "sched_process_exec",
			ProcessKey:     "uid:18",
			ContainerID:    "abc123container",
			ExecutablePath: "/usr/bin/python3.10",
			Fields: map[string]any{
				"pathname": "/usr/bin/python3.10",
				"argv":     []string{"python3", "/app/AppUpdates/updater.py"},
				"dev":      uint32(51),
				"inode":    uint64(999),
			},
		},
		{
			Index:      2,
			Timestamp:  time.Now(),
			EventName:  "file_modification",
			ProcessKey: "uid:2",
			Fields: map[string]any{
				"file_path": "/app/AppUpdates/updater.py",
				"dev":       uint32(265289729),
				"inode":     uint64(354727),
			},
		},
		{
			Index:      3,
			Timestamp:  time.Now(),
			EventName:  "decoy_file_read",
			ProcessKey: "uid:18",
			IsIOC:      true,
			Fields: map[string]any{
				"file_path": "/root/.kube",
			},
		},
	}

	builder := newTestBuilder(t, events)
	out := model.Output{
		ProcessTree: model.ProcessTree{Nodes: builder.Nodes()},
		IOCs:        builder.IOCs(),
		PathDevInode: builder.PathDevInodeIndex(),
	}

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	payloadContent := []byte("print('malicious')\n")
	writeTestArtifactsZip(t, zipPath, "abc123container", 265289729, 354727, payloadContent)

	enriched, err := EnrichPayloads(out, zipPath)
	require.NoError(t, err)
	require.Len(t, enriched.IOCs, 1)

	payload := enriched.IOCs[0].Payload
	require.NotNil(t, payload)
	assert.Equal(t, "/app/AppUpdates/updater.py", payload.Path)
	assert.Equal(t, uint32(265289729), payload.Dev)
	assert.Equal(t, uint64(354727), payload.Inode)
	assert.Equal(t, model.PayloadStatusFound, payload.Status)
	assert.NotEmpty(t, payload.SHA256)
	assert.Contains(t, payload.ArtifactPath, "write.dev-265289729.inode-354727")
	assert.Equal(t, model.PayloadCategoryScript, payload.FileCategory)
	assert.Equal(t, model.PayloadTypePython, payload.FileType)
}

func TestEnrichPayloadsWithoutArtifactsZip(t *testing.T) {
	t.Parallel()

	events := []model.NormalizedEvent{
		{
			Index:      1,
			Timestamp:  time.Now(),
			EventName:  "sched_process_exec",
			ProcessKey: "uid:17",
			Fields: map[string]any{
				"pathname": "/app/AppUpdates/updater",
				"argv":     []string{"/app/AppUpdates/updater", "skip"},
				"dev":      uint32(51),
				"inode":    uint64(354726),
			},
		},
		{
			Index:      2,
			Timestamp:  time.Now(),
			EventName:  "decoy_file_read",
			ProcessKey: "uid:17",
			IsIOC:      true,
		},
	}

	builder := newTestBuilder(t, events)
	out := model.Output{
		ProcessTree: model.ProcessTree{Nodes: builder.Nodes()},
		IOCs:        builder.IOCs(),
		PathDevInode: builder.PathDevInodeIndex(),
	}

	enriched, err := EnrichPayloads(out, "")
	require.NoError(t, err)
	require.Len(t, enriched.IOCs, 1)

	payload := enriched.IOCs[0].Payload
	require.NotNil(t, payload)
	assert.Equal(t, "/app/AppUpdates/updater", payload.Path)
	assert.Equal(t, uint32(51), payload.Dev)
	assert.Equal(t, uint64(354726), payload.Inode)
	assert.Empty(t, payload.SHA256)
	assert.Empty(t, payload.Status)
}

func TestEnrichPayloadsWithCommittedZipFixture(t *testing.T) {
	t.Parallel()

	events := []model.NormalizedEvent{
		{
			Index:          1,
			Timestamp:      time.Now(),
			EventName:      "sched_process_exec",
			ProcessKey:     "uid:18",
			ContainerID:    "1764ed076193a786850beda1b6da422d21a68f69dd6d3d029d2348282bc1ff64",
			ExecutablePath: "/usr/bin/python3.10",
			Fields: map[string]any{
				"pathname": "/usr/bin/python3.10",
				"argv":     []string{"python3", "/app/AppUpdates/updater.py"},
			},
		},
		{
			Index:      2,
			Timestamp:  time.Now(),
			EventName:  "file_modification",
			ProcessKey: "uid:2",
			Fields: map[string]any{
				"file_path": "/app/AppUpdates/updater.py",
				"dev":       uint32(265289729),
				"inode":     uint64(354727),
			},
		},
		{
			Index:      3,
			Timestamp:  time.Now(),
			EventName:  "non_whitelisted_domain_connection",
			ProcessKey: "uid:18",
			IsIOC:      true,
		},
	}

	builder := newTestBuilder(t, events)
	out := model.Output{
		ProcessTree:  model.ProcessTree{Nodes: builder.Nodes()},
		IOCs:         builder.IOCs(),
		PathDevInode: builder.PathDevInodeIndex(),
	}

	enriched, err := EnrichPayloads(out, "../../testdata/artifacts_minimal.zip")
	require.NoError(t, err)
	require.Len(t, enriched.IOCs, 1)
	assert.Equal(t, model.PayloadStatusFound, enriched.IOCs[0].Payload.Status)
	assert.NotEmpty(t, enriched.IOCs[0].Payload.SHA256)
}

func TestEnrichPayloadsFromFixture(t *testing.T) {
	t.Parallel()

	f, err := os.Open("../../testdata/sample.ndjson")
	require.NoError(t, err)
	defer f.Close()

	events, err := input.ReadEvents(f)
	require.NoError(t, err)

	out := FromEvents(events, model.DefaultBuildOptions())
	enriched, err := EnrichPayloads(out, "")
	require.NoError(t, err)
	require.NotEmpty(t, enriched.IOCs)
	assert.NotNil(t, enriched.IOCs[0].Payload)
}

func newTestBuilder(t *testing.T, events []model.NormalizedEvent) *testBuilder {
	t.Helper()

	out := FromEvents(events, model.DefaultBuildOptions())
	return &testBuilder{out: out}
}

type testBuilder struct {
	out model.Output
}

func (b *testBuilder) Nodes() map[string]model.ProcessNode {
	return b.out.ProcessTree.Nodes
}

func (b *testBuilder) IOCs() []model.IOCRecord {
	return b.out.IOCs
}

func (b *testBuilder) PathDevInodeIndex() map[string][]model.DevInodeRef {
	return b.out.PathDevInode
}

func writeTestArtifactsZip(t *testing.T, zipPath, containerID string, dev uint32, inode uint64, content []byte) {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	entryPath := filepath.Join(
		"run", "artifacts", "out", containerID,
		"write.dev-"+formatUint32(dev)+".inode-"+formatUint64(inode),
	)
	f, err := writer.Create(entryPath)
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o644))
}

func formatUint32(v uint32) string {
	return formatUint64(uint64(v))
}

func formatUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for v > 0 {
		i--
		digits[i] = byte('0' + v%10)
		v /= 10
	}
	return string(digits[i:])
}

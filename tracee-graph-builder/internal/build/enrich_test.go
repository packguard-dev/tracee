package build

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

const (
	testFileCtime  = uint64(1780820471644394172)
	testArtifactDev = uint64(50)
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
				"inode":    uint64(999),
				"ctime":    uint64(111),
			},
		},
		{
			Index:       2,
			Timestamp:   time.Now(),
			EventName:   "file_modification",
			ProcessKey:  "uid:2",
			ContainerID: "abc123container",
			Fields: map[string]any{
				"file_path": "/app/AppUpdates/updater.py",
				"inode":     uint64(354727),
				"ctime":     testFileCtime,
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
		ProcessTree:      model.ProcessTree{Nodes: builder.Nodes()},
		IOCs:             builder.IOCs(),
		PathFileIdentity: builder.PathFileIdentityIndex(),
	}

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	payloadPath := "/app/AppUpdates/updater.py"
	payloadContent := []byte("print('malicious')\n")
	writeTestArtifactsZip(t, zipPath, "abc123container", 354727, payloadContent, payloadPath)

	enriched, err := EnrichPayloads(out, zipPath)
	require.NoError(t, err)
	require.Len(t, enriched.IOCs, 1)

	payload := enriched.IOCs[0].Payload
	require.NotNil(t, payload)
	assert.Equal(t, payloadPath, payload.Path)
	assert.Equal(t, uint64(354727), payload.Inode)
	assert.Equal(t, testFileCtime, payload.Ctime)
	assert.Equal(t, model.PayloadStatusFound, payload.Status)
	assert.NotEmpty(t, payload.SHA256)
	assert.Contains(t, payload.ArtifactPath, "write.dev-50.inode-354727")
	assert.Equal(t, model.PayloadCategoryScript, payload.FileCategory)
	assert.Equal(t, model.PayloadTypePython, payload.FileType)
}

func TestEnrichPayloadsWithoutArtifactsZip(t *testing.T) {
	t.Parallel()

	events := []model.NormalizedEvent{
		{
			Index:       1,
			Timestamp:   time.Now(),
			EventName:   "sched_process_exec",
			ProcessKey:  "uid:17",
			ContainerID: "abc123container",
			Fields: map[string]any{
				"pathname": "/app/AppUpdates/updater",
				"argv":     []string{"/app/AppUpdates/updater", "skip"},
				"inode":    uint64(354726),
				"ctime":    testFileCtime,
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
		ProcessTree:      model.ProcessTree{Nodes: builder.Nodes()},
		IOCs:             builder.IOCs(),
		PathFileIdentity: builder.PathFileIdentityIndex(),
	}

	enriched, err := EnrichPayloads(out, "")
	require.NoError(t, err)
	require.Len(t, enriched.IOCs, 1)

	payload := enriched.IOCs[0].Payload
	require.NotNil(t, payload)
	assert.Equal(t, "/app/AppUpdates/updater", payload.Path)
	assert.Equal(t, uint64(354726), payload.Inode)
	assert.Equal(t, testFileCtime, payload.Ctime)
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
			Index:       2,
			Timestamp:   time.Now(),
			EventName:   "file_modification",
			ProcessKey:  "uid:2",
			ContainerID: "1764ed076193a786850beda1b6da422d21a68f69dd6d3d029d2348282bc1ff64",
			Fields: map[string]any{
				"file_path": "/app/AppUpdates/updater.py",
				"inode":     uint64(354727),
				"ctime":     testFileCtime,
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
		ProcessTree:      model.ProcessTree{Nodes: builder.Nodes()},
		IOCs:             builder.IOCs(),
		PathFileIdentity: builder.PathFileIdentityIndex(),
	}

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	writeTestArtifactsZip(
		t,
		zipPath,
		"1764ed076193a786850beda1b6da422d21a68f69dd6d3d029d2348282bc1ff64",
		354727,
		[]byte("print('malicious')\n"),
		"/app/AppUpdates/updater.py",
	)

	enriched, err := EnrichPayloads(out, zipPath)
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

func (b *testBuilder) PathFileIdentityIndex() map[string][]model.FileIdentityRef {
	return b.out.PathFileIdentity
}

func writeTestArtifactsZip(t *testing.T, zipPath, containerID string, inode uint64, content []byte, payloadPath string) {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	artifactName := fmt.Sprintf("write.dev-%d.inode-%d", testArtifactDev, inode)
	entryPath := filepath.Join(
		"run", "artifacts", "out", containerID,
		artifactName,
	)
	f, err := writer.Create(entryPath)
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)

	indexPath := filepath.Join("run", "artifacts", "out", "written_files")
	indexContent := containerID + "/" + artifactName + " " + payloadPath + "\n"
	f, err = writer.Create(indexPath)
	require.NoError(t, err)
	_, err = f.Write([]byte(indexContent))
	require.NoError(t, err)

	require.NoError(t, writer.Close())
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o644))
}

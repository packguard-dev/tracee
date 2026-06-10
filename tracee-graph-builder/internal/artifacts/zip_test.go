package artifacts

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testArtifactDev = uint64(50)

func TestFindWriteArtifact(t *testing.T) {
	t.Parallel()

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	containerID := "1764ed076193a786850beda1b6da422d21a68f69dd6d3d029d2348282bc1ff64"
	payloadPath := "/app/AppUpdates/updater.py"
	content := []byte("#!/usr/bin/env python3\nprint('payload')\n")
	writeMinimalZip(t, zipPath, containerID, 354727, content, payloadPath)

	store, err := Open(zipPath)
	require.NoError(t, err)
	defer store.Close()

	data, entryPath, err := store.FindWriteArtifact(containerID, payloadPath, []uint64{354727})
	require.NoError(t, err)
	assert.Equal(t, content, data)
	assert.Contains(t, entryPath, "write.dev-50.inode-354727")

	hash := SHA256Hex(data)
	assert.Len(t, hash, 64)
}

func TestFindWriteArtifactHostContainer(t *testing.T) {
	t.Parallel()

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	payloadPath := "/payload/path"
	content := []byte("host payload")
	writeMinimalZip(t, zipPath, "host", 1966101, content, payloadPath)

	store, err := Open(zipPath)
	require.NoError(t, err)
	defer store.Close()

	data, _, err := store.FindWriteArtifact("", payloadPath, []uint64{1966101})
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestOpenOptionalEmptyPath(t *testing.T) {
	t.Parallel()

	store, err := OpenOptional("")
	require.NoError(t, err)
	assert.Nil(t, store)
}

func TestFindWriteArtifactFromDir(t *testing.T) {
	t.Parallel()

	dirRoot := filepath.Join(t.TempDir(), "artifacts")
	containerID := "1764ed076193a786850beda1b6da422d21a68f69dd6d3d029d2348282bc1ff64"
	payloadPath := "/app/AppUpdates/updater.py"
	content := []byte("#!/usr/bin/env python3\nprint('payload')\n")
	writeMinimalDir(t, dirRoot, containerID, 354727, content, payloadPath)

	store, err := OpenDir(dirRoot)
	require.NoError(t, err)
	defer store.Close()

	data, entryPath, err := store.FindWriteArtifact(containerID, payloadPath, []uint64{354727})
	require.NoError(t, err)
	assert.Equal(t, content, data)
	assert.Contains(t, entryPath, "write.dev-50.inode-354727")
}

func TestOpenOptionalDir(t *testing.T) {
	t.Parallel()

	dirRoot := filepath.Join(t.TempDir(), "artifacts")
	payloadPath := "/payload/path"
	content := []byte("host payload")
	writeMinimalDir(t, dirRoot, "host", 1966101, content, payloadPath)

	store, err := OpenOptional(dirRoot)
	require.NoError(t, err)
	defer store.Close()

	data, _, err := store.FindWriteArtifact("", payloadPath, []uint64{1966101})
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestFindWriteArtifactDisambiguatesByPathAndInode(t *testing.T) {
	t.Parallel()

	dirRoot := filepath.Join(t.TempDir(), "artifacts")
	containerID := "73fc704cb71e536968b4dc03b8c21a8cb4f2784fd1b5760787ea589a35b89a74"
	baseDir := filepath.Join(dirRoot, "run", "artifacts", "out", containerID)
	require.NoError(t, os.MkdirAll(baseDir, 0o755))

	entries := []struct {
		inode uint64
		path  string
		data  []byte
	}{
		{355699, "/app/node_modules/synckit/AppUpdates/updater.js", []byte("js payload")},
		{355700, "/app/node_modules/synckit/AppUpdates/updater", []byte("bin payload")},
		{355701, "/app/node_modules/synckit/AppUpdates/updater.py", []byte("py payload")},
	}

	var indexLines []string
	for _, entry := range entries {
		artifactName := traceeArtifactName(testArtifactDev, entry.inode)
		entryPath := filepath.Join(baseDir, artifactName)
		require.NoError(t, os.WriteFile(entryPath, entry.data, 0o644))
		indexLines = append(indexLines, fmt.Sprintf(
			"%s/%s %s",
			containerID,
			artifactName,
			entry.path,
		))
	}

	indexPath := filepath.Join(dirRoot, "run", "artifacts", "out", "written_files")
	require.NoError(t, os.WriteFile(indexPath, []byte(stringsJoinLines(indexLines)), 0o644))

	store, err := OpenDir(dirRoot)
	require.NoError(t, err)
	defer store.Close()

	data, entryPath, err := store.FindWriteArtifact(
		containerID,
		"/app/node_modules/synckit/AppUpdates/updater.js",
		[]uint64{355699},
	)
	require.NoError(t, err)
	assert.Equal(t, []byte("js payload"), data)
	assert.Contains(t, entryPath, "write.dev-50.inode-355699")
}

func TestFindWriteArtifactInodeOnlyFallback(t *testing.T) {
	t.Parallel()

	dirRoot := filepath.Join(t.TempDir(), "artifacts")
	containerID := "73fc704cb71e536968b4dc03b8c21a8cb4f2784fd1b5760787ea589a35b89a74"
	payloadPath := "/app/node_modules/synckit/AppUpdates/updater.py"
	writtenPath := "/var/lib/containers/storage/overlay/diff/app/node_modules/synckit/AppUpdates/updater.py"
	content := []byte("py payload from overlay path")

	baseDir := filepath.Join(dirRoot, "run", "artifacts", "out", containerID)
	artifactName := traceeArtifactName(testArtifactDev, 355701)
	require.NoError(t, os.MkdirAll(baseDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(baseDir, artifactName), content, 0o644))

	indexContent := containerID + "/" + artifactName + " " + writtenPath + "\n"
	indexPath := filepath.Join(dirRoot, "run", "artifacts", "out", "written_files")
	require.NoError(t, os.WriteFile(indexPath, []byte(indexContent), 0o644))

	store, err := OpenDir(dirRoot)
	require.NoError(t, err)
	defer store.Close()

	data, entryPath, err := store.FindWriteArtifact(containerID, payloadPath, []uint64{355701})
	require.NoError(t, err)
	assert.Equal(t, content, data)
	assert.Contains(t, entryPath, "write.dev-50.inode-355701")
}

func TestFindWriteArtifactByPathOnly(t *testing.T) {
	t.Parallel()

	dirRoot := filepath.Join(t.TempDir(), "artifacts")
	containerID := "73fc704cb71e536968b4dc03b8c21a8cb4f2784fd1b5760787ea589a35b89a74"
	payloadPath := "/app/node_modules/synckit/AppUpdates/updater.py"
	content := []byte("py payload")
	writeMinimalDir(t, dirRoot, containerID, 355701, content, payloadPath)

	store, err := OpenDir(dirRoot)
	require.NoError(t, err)
	defer store.Close()

	data, entryPath, err := store.FindWriteArtifact(containerID, payloadPath, nil)
	require.NoError(t, err)
	assert.Equal(t, content, data)
	assert.Contains(t, entryPath, "write.dev-50.inode-355701")

	inode, ok := store.InodeFromWrittenFile(containerID, payloadPath)
	require.True(t, ok)
	assert.Equal(t, uint64(355701), inode)
}

func TestParseWrittenFileLine(t *testing.T) {
	t.Parallel()

	entry, ok := parseWrittenFileLine(
		"73fc704cb71e536968b4dc03b8c21a8cb4f2784fd1b5760787ea589a35b89a74/write.dev-50.inode-355699 /app/node_modules/synckit/AppUpdates/updater.js",
	)
	require.True(t, ok)
	assert.Equal(t, uint64(355699), entry.inode)
	assert.Equal(t, "/app/node_modules/synckit/AppUpdates/updater.js", entry.pathname)
	assert.Equal(t, "write.dev-50.inode-355699", entry.basename)
}

func writeMinimalDir(t *testing.T, dirRoot, containerID string, inode uint64, content []byte, payloadPath string) {
	t.Helper()

	artifactName := traceeArtifactName(testArtifactDev, inode)
	entryPath := filepath.Join(
		dirRoot, "run", "artifacts", "out", containerID,
		artifactName,
	)
	require.NoError(t, os.MkdirAll(filepath.Dir(entryPath), 0o755))
	require.NoError(t, os.WriteFile(entryPath, content, 0o644))

	indexPath := filepath.Join(dirRoot, "run", "artifacts", "out", "written_files")
	indexContent := containerID + "/" + artifactName + " " + payloadPath + "\n"
	require.NoError(t, os.WriteFile(indexPath, []byte(indexContent), 0o644))
}

func writeMinimalZip(t *testing.T, zipPath, containerID string, inode uint64, content []byte, payloadPath string) {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)

	artifactName := traceeArtifactName(testArtifactDev, inode)
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

func traceeArtifactName(dev, inode uint64) string {
	return fmt.Sprintf("write.dev-%d.inode-%d", dev, inode)
}

func stringsJoinLines(lines []string) string {
	out := ""
	for i, line := range lines {
		if i > 0 {
			out += "\n"
		}
		out += line
	}
	return out
}

package artifacts

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestFindWriteArtifact(t *testing.T) {
	t.Parallel()

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	containerID := "1764ed076193a786850beda1b6da422d21a68f69dd6d3d029d2348282bc1ff64"
	content := []byte("#!/usr/bin/env python3\nprint('payload')\n")
	writeMinimalZip(t, zipPath, containerID, 265289729, 354727, content)

	store, err := Open(zipPath)
	require.NoError(t, err)
	defer store.Close()

	candidates := []model.DevInodeRef{{Dev: 265289729, Inode: 354727}}
	data, entryPath, err := store.FindWriteArtifact(containerID, candidates)
	require.NoError(t, err)
	assert.Equal(t, content, data)
	assert.Contains(t, entryPath, "write.dev-265289729.inode-354727")

	hash := SHA256Hex(data)
	assert.Len(t, hash, 64)
}

func TestFindWriteArtifactHostContainer(t *testing.T) {
	t.Parallel()

	zipPath := filepath.Join(t.TempDir(), "artifacts.zip")
	content := []byte("host payload")
	writeMinimalZip(t, zipPath, "host", 271581185, 1966101, content)

	store, err := Open(zipPath)
	require.NoError(t, err)
	defer store.Close()

	candidates := []model.DevInodeRef{{Dev: 271581185, Inode: 1966101}}
	data, _, err := store.FindWriteArtifact("", candidates)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestOpenOptionalEmptyPath(t *testing.T) {
	t.Parallel()

	store, err := OpenOptional("")
	require.NoError(t, err)
	assert.Nil(t, store)
}

func writeMinimalZip(t *testing.T, zipPath, containerID string, dev uint32, inode uint64, content []byte) {
	t.Helper()

	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)

	entryPath := filepath.Join(
		"run", "artifacts", "out", containerID,
		"write.dev-"+itoa(dev)+".inode-"+uitoa(inode),
	)
	f, err := writer.Create(entryPath)
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)

	indexPath := filepath.Join("run", "artifacts", "out", "written_files")
	indexContent := containerID + "/write.dev-" + itoa(dev) + ".inode-" + uitoa(inode) + " /payload/path\n"
	f, err = writer.Create(indexPath)
	require.NoError(t, err)
	_, err = f.Write([]byte(indexContent))
	require.NoError(t, err)

	require.NoError(t, writer.Close())
	require.NoError(t, os.WriteFile(zipPath, buf.Bytes(), 0o644))
}

func itoa(v uint32) string {
	return fmtUint(uint64(v))
}

func uitoa(v uint64) string {
	return fmtUint(v)
}

func fmtUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

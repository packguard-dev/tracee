package artifacts

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

// Store provides read access to file-write artifacts inside a zip archive.
type Store struct {
	reader       *zip.ReadCloser
	entries      map[string]*zip.File
	writtenFiles map[string]string // artifact key -> pathname
}

// Open loads an artifacts zip archive.
func Open(path string) (*Store, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open artifacts zip: %w", err)
	}

	store := &Store{
		reader:       reader,
		entries:      make(map[string]*zip.File, len(reader.File)),
		writtenFiles: make(map[string]string),
	}
	for _, file := range reader.File {
		store.entries[normalizeZipPath(file.Name)] = file
	}
	store.parseWrittenFiles()
	return store, nil
}

// Close releases the underlying zip reader.
func (s *Store) Close() error {
	if s == nil || s.reader == nil {
		return nil
	}
	return s.reader.Close()
}

// FindWriteArtifact locates a write artifact for the given container, dev, and inode.
func (s *Store) FindWriteArtifact(containerID string, candidates []model.DevInodeRef) ([]byte, string, error) {
	if s == nil {
		return nil, "", fmt.Errorf("artifacts store is nil")
	}

	containerID = normalizeContainerID(containerID)
	artifactName := func(dev uint32, inode uint64) string {
		return fmt.Sprintf("write.dev-%d.inode-%d", dev, inode)
	}

	for _, ref := range candidates {
		name := artifactName(ref.Dev, ref.Inode)
		if data, entryPath, ok := s.readEntryBySuffix(containerID, name); ok {
			return data, entryPath, nil
		}
	}

	for _, ref := range candidates {
		key := fmt.Sprintf("%s/%s", containerID, artifactName(ref.Dev, ref.Inode))
		if pathname, ok := s.writtenFiles[key]; ok && pathname != "" {
			if data, entryPath, ok := s.readEntryBySuffix(containerID, artifactName(ref.Dev, ref.Inode)); ok {
				return data, entryPath, nil
			}
		}
	}

	return nil, "", fmt.Errorf("artifact not found in zip for container %s", containerID)
}

// SHA256Hex returns the lowercase hex SHA256 digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *Store) readEntryBySuffix(containerID, artifactName string) ([]byte, string, bool) {
	suffix := path.Join(containerID, artifactName)
	for entryPath, file := range s.entries {
		if strings.HasSuffix(entryPath, suffix) || strings.HasSuffix(entryPath, artifactName) {
			if containerID != "host" && !strings.Contains(entryPath, containerID) {
				continue
			}
			data, err := readZipFile(file)
			if err != nil {
				continue
			}
			return data, entryPath, true
		}
	}
	return nil, "", false
}

func (s *Store) parseWrittenFiles() {
	for entryPath, file := range s.entries {
		base := path.Base(entryPath)
		if base != "written_files" {
			continue
		}
		data, err := readZipFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			s.writtenFiles[parts[0]] = parts[1]
		}
	}
}

func readZipFile(file *zip.File) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func normalizeZipPath(name string) string {
	return path.Clean(strings.ReplaceAll(name, "\\", "/"))
}

func normalizeContainerID(containerID string) string {
	if containerID == "" {
		return "host"
	}
	return containerID
}

// OpenOptional opens the artifacts zip when path is non-empty.
func OpenOptional(path string) (*Store, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("artifacts zip: %w", err)
	}
	return Open(path)
}

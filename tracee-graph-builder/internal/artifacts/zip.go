package artifacts

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

var inodeFromBasenameRE = regexp.MustCompile(`\.inode-(\d+)`)

type artifactEntry struct {
	zipFile  *zip.File
	filePath string
}

type writtenFileEntry struct {
	artifactKey string
	containerID string
	inode       uint64
	pathname    string
	basename    string
}

func (e *writtenFileEntry) lookupKey() string {
	return fmt.Sprintf("%s\x00%s\x00%d", e.containerID, e.pathname, e.inode)
}

func (e *writtenFileEntry) inodeLookupKey() string {
	return fmt.Sprintf("%s\x00%d", e.containerID, e.inode)
}

func parseInodeFromArtifactBasename(name string) (uint64, bool) {
	matches := inodeFromBasenameRE.FindStringSubmatch(name)
	if len(matches) < 2 {
		return 0, false
	}
	inode, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

func splitWrittenFileKey(key string) (containerID, basename string, ok bool) {
	key = strings.TrimSpace(key)
	slash := strings.Index(key, "/")
	if slash <= 0 || slash >= len(key)-1 {
		return "", "", false
	}
	return key[:slash], key[slash+1:], true
}

func parseWrittenFileLine(line string) (writtenFileEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return writtenFileEntry{}, false
	}

	space := strings.IndexByte(line, ' ')
	if space <= 0 || space >= len(line)-1 {
		return writtenFileEntry{}, false
	}

	artifactKey := strings.TrimSpace(line[:space])
	pathname := strings.TrimSpace(line[space+1:])
	if artifactKey == "" || pathname == "" {
		return writtenFileEntry{}, false
	}

	containerID, basename, ok := splitWrittenFileKey(artifactKey)
	if !ok {
		return writtenFileEntry{}, false
	}

	inode, ok := parseInodeFromArtifactBasename(basename)
	if !ok {
		return writtenFileEntry{}, false
	}

	return writtenFileEntry{
		artifactKey: artifactKey,
		containerID: model.NormalizeContainerID(containerID),
		inode:       inode,
		pathname:    pathname,
		basename:    basename,
	}, true
}

// Store provides read access to file-write artifacts in a zip archive or directory.
type Store struct {
	reader       *zip.ReadCloser
	entries      map[string]*artifactEntry
	writtenFiles        []writtenFileEntry
	writtenIndex        map[string]writtenFileEntry
	writtenIndexByInode map[string]writtenFileEntry
}

// Open loads an artifacts zip archive.
func Open(path string) (*Store, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open artifacts zip: %w", err)
	}

	store := &Store{
		reader:              reader,
		entries:             make(map[string]*artifactEntry, len(reader.File)),
		writtenIndex:        make(map[string]writtenFileEntry),
		writtenIndexByInode: make(map[string]writtenFileEntry),
	}
	for _, file := range reader.File {
		store.entries[normalizeZipPath(file.Name)] = &artifactEntry{zipFile: file}
	}
	store.parseWrittenFiles()
	return store, nil
}

// OpenDir loads artifacts from an extracted directory tree.
func OpenDir(root string) (*Store, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("open artifacts dir: %w", err)
	}

	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("open artifacts dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("open artifacts dir: %s is not a directory", absRoot)
	}

	store := &Store{
		entries:             make(map[string]*artifactEntry),
		writtenIndex:        make(map[string]writtenFileEntry),
		writtenIndexByInode: make(map[string]writtenFileEntry),
	}
	err = filepath.WalkDir(absRoot, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(absRoot, filePath)
		if err != nil {
			return err
		}
		store.entries[normalizeZipPath(rel)] = &artifactEntry{filePath: filePath}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("open artifacts dir: %w", err)
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

// FindWriteArtifact locates a write artifact for the given container, payload path, and inode candidates.
func (s *Store) FindWriteArtifact(containerID, payloadPath string, inodes []uint64) ([]byte, string, error) {
	if s == nil {
		return nil, "", fmt.Errorf("artifacts store is nil")
	}
	if payloadPath == "" {
		return nil, "", fmt.Errorf("payload path is empty")
	}

	containerID = model.NormalizeContainerID(containerID)

	for _, inode := range inodes {
		entry, ok := s.lookupWrittenFile(containerID, payloadPath, inode)
		if !ok {
			continue
		}
		if data, entryPath, ok := s.readEntryBySuffix(containerID, entry.basename); ok {
			return data, entryPath, nil
		}
	}

	for _, inode := range inodes {
		entry, ok := s.lookupWrittenFileByInode(containerID, inode)
		if !ok {
			continue
		}
		if data, entryPath, ok := s.readEntryBySuffix(containerID, entry.basename); ok {
			return data, entryPath, nil
		}
	}

	if entry, ok := s.lookupWrittenFileByPath(containerID, payloadPath); ok {
		if data, entryPath, ok := s.readEntryBySuffix(containerID, entry.basename); ok {
			return data, entryPath, nil
		}
	}

	return nil, "", fmt.Errorf(
		"artifact not found for container %s path %s",
		containerID,
		payloadPath,
	)
}

// SHA256Hex returns the lowercase hex SHA256 digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *Store) lookupWrittenFile(containerID, payloadPath string, inode uint64) (writtenFileEntry, bool) {
	key := fmt.Sprintf("%s\x00%s\x00%d", containerID, payloadPath, inode)
	entry, ok := s.writtenIndex[key]
	return entry, ok
}

func (s *Store) lookupWrittenFileByPath(containerID, payloadPath string) (writtenFileEntry, bool) {
	for _, entry := range s.writtenFiles {
		if entry.containerID == containerID && entry.pathname == payloadPath {
			return entry, true
		}
	}
	return writtenFileEntry{}, false
}

func (s *Store) lookupWrittenFileByInode(containerID string, inode uint64) (writtenFileEntry, bool) {
	key := fmt.Sprintf("%s\x00%d", containerID, inode)
	entry, ok := s.writtenIndexByInode[key]
	return entry, ok
}

// InodeFromWrittenFile returns the inode for a payload path in written_files, if present.
func (s *Store) InodeFromWrittenFile(containerID, payloadPath string) (uint64, bool) {
	entry, ok := s.lookupWrittenFileByPath(containerID, payloadPath)
	if !ok {
		return 0, false
	}
	return entry.inode, true
}

func (s *Store) readEntryBySuffix(containerID, artifactName string) ([]byte, string, bool) {
	suffix := path.Join(containerID, artifactName)
	for entryPath, entry := range s.entries {
		if strings.HasSuffix(entryPath, suffix) || strings.HasSuffix(entryPath, artifactName) {
			if containerID != "host" && !strings.Contains(entryPath, containerID) {
				continue
			}
			data, err := entry.read()
			if err != nil {
				continue
			}
			return data, entryPath, true
		}
	}
	return nil, "", false
}

func (s *Store) parseWrittenFiles() {
	for entryPath, entry := range s.entries {
		base := path.Base(entryPath)
		if base != "written_files" {
			continue
		}
		data, err := entry.read()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			parsed, ok := parseWrittenFileLine(line)
			if !ok {
				continue
			}
			s.writtenFiles = append(s.writtenFiles, parsed)
			s.writtenIndex[parsed.lookupKey()] = parsed
			if _, exists := s.writtenIndexByInode[parsed.inodeLookupKey()]; !exists {
				s.writtenIndexByInode[parsed.inodeLookupKey()] = parsed
			}
		}
	}
}

func (e *artifactEntry) read() ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("artifact entry is nil")
	}
	if e.zipFile != nil {
		return readZipFile(e.zipFile)
	}
	return os.ReadFile(e.filePath)
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

// OpenOptional opens artifacts from a zip file or directory when path is non-empty.
func OpenOptional(path string) (*Store, error) {
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("artifacts: %w", err)
	}
	if info.IsDir() {
		return OpenDir(path)
	}
	return Open(path)
}

package payload

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestClassifyEmptyContent(t *testing.T) {
	t.Parallel()

	c := Classify("/tmp/payload.py", nil)
	assert.Empty(t, c.Category)
	assert.Empty(t, c.Type)
}

func TestClassifyPythonScript(t *testing.T) {
	t.Parallel()

	content := []byte("print('malicious')\n")
	c := Classify("/app/AppUpdates/updater.py", content)
	assert.Equal(t, model.PayloadCategoryScript, c.Category)
	assert.Equal(t, model.PayloadTypePython, c.Type)
}

func TestClassifyJavaScriptScript(t *testing.T) {
	t.Parallel()

	content := []byte("console.log('hello');\n")
	c := Classify("app.js", content)
	assert.Equal(t, model.PayloadCategoryScript, c.Category)
	assert.Equal(t, model.PayloadTypeJavaScript, c.Type)
}

func TestClassifyBashScript(t *testing.T) {
	t.Parallel()

	content := []byte("#!/bin/bash\necho hello\n")
	c := Classify("run.sh", content)
	assert.Equal(t, model.PayloadCategoryScript, c.Category)
	assert.Equal(t, model.PayloadTypeBash, c.Type)
}

func TestClassifyELFExecutable(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skip("ELF fixture requires linux")
	}

	content, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skipf("read ELF fixture: %v", err)
	}

	c := Classify("/usr/bin/true", content)
	assert.Equal(t, model.PayloadCategoryExecutable, c.Category)
	assert.Equal(t, model.PayloadTypeELF, c.Type)
}

func TestClassifyPEExecutable(t *testing.T) {
	t.Parallel()

	content := readTestdata(t, "pe-exec.bin")
	c := Classify("program.exe", content)
	assert.Equal(t, model.PayloadCategoryExecutable, c.Category)
	assert.Equal(t, model.PayloadTypePE, c.Type)
}

func TestClassifyDLL(t *testing.T) {
	t.Parallel()

	raw := readTestdata(t, "pe-exec.bin")
	content := append([]byte(nil), raw...)
	patchPECharacteristics(t, content, true)

	c := Classify("library.dll", content)
	assert.Equal(t, model.PayloadCategoryExecutable, c.Category)
	assert.Equal(t, model.PayloadTypeDLL, c.Type)
}

func TestClassifyGenericBinary(t *testing.T) {
	t.Parallel()

	content := make([]byte, 256)
	for i := range content {
		content[i] = byte(i)
	}

	c := Classify("payload.bin", content)
	assert.Equal(t, model.PayloadCategoryExecutable, c.Category)
	assert.Equal(t, model.PayloadTypeBinary, c.Type)
}

func TestApplyClassification(t *testing.T) {
	t.Parallel()

	info := &model.PayloadInfo{Path: "/app/updater.py"}
	ApplyClassification(info, info.Path, []byte("print('x')\n"))
	assert.Equal(t, model.PayloadCategoryScript, info.FileCategory)
	assert.Equal(t, model.PayloadTypePython, info.FileType)
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", name)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	return content
}

func peCharacteristicsOffset(content []byte) int {
	if len(content) < 0x40 {
		return 0
	}
	peOffset := int(binary.LittleEndian.Uint32(content[0x3C:]))
	return peOffset + 4 + 18
}

func patchPECharacteristics(t *testing.T, content []byte, dll bool) {
	t.Helper()

	offset := peCharacteristicsOffset(content)
	require.Greater(t, len(content), offset+2)
	value := binary.LittleEndian.Uint16(content[offset:])
	if dll {
		value |= 0x2000
	}
	binary.LittleEndian.PutUint16(content[offset:], value)
}

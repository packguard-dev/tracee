package output

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/build"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestEncodeJSON(t *testing.T) {
	t.Parallel()

	out := sampleOutput(t)
	encoded, err := Encode(FormatJSON, out)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(encoded), "{\n"))
	assert.Contains(t, string(encoded), `"iocs"`)
	assert.NotContains(t, string(encoded), `"container_id"`)
}

func TestEncodeTable(t *testing.T) {
	t.Parallel()

	out := sampleOutput(t)
	encoded, err := Encode(FormatTable, out)
	require.NoError(t, err)
	text := string(encoded)

	assert.Contains(t, text, "IOCs")
	assert.Contains(t, text, "Process trees")
	assert.Contains(t, text, "Files")
	assert.Contains(t, text, "Network")
	assert.Contains(t, text, "decoy_file_read")
	assert.Contains(t, text, "/etc/shadow")
	assert.Contains(t, text, "READ:")
	assert.Contains(t, text, "WRITE:")
	assert.Contains(t, text, "RENAME:")
	assert.Contains(t, text, "DELETE:")
	assert.Contains(t, text, "uid:10001")
	assert.NotContains(t, text, "container:")
}

func TestEncodeUnsupportedFormat(t *testing.T) {
	t.Parallel()

	_, err := Encode("yaml", model.Output{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

func sampleOutput(t *testing.T) model.Output {
	t.Helper()

	f, err := os.Open("../../testdata/sample.ndjson")
	require.NoError(t, err)
	defer f.Close()

	events, err := input.ReadEvents(f)
	require.NoError(t, err)

	return build.FromEvents(events, model.DefaultBuildOptions())
}

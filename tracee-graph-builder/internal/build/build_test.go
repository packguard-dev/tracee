package build

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/input"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestFromEventsFixture(t *testing.T) {
	t.Parallel()

	f, err := os.Open("../../testdata/sample.ndjson")
	require.NoError(t, err)
	defer f.Close()

	events, err := input.ReadEvents(f)
	require.NoError(t, err)

	output := FromEvents(events, model.DefaultBuildOptions())
	assert.Equal(t, len(events), output.Meta.InputEvents)
	assert.NotEmpty(t, output.ProcessTree.Nodes)
	assert.NotEmpty(t, output.Files.Read)
	assert.NotEmpty(t, output.Files.Write)
	assert.NotEmpty(t, output.Files.Rename)
	assert.NotEmpty(t, output.Files.Delete)
	assert.NotEmpty(t, output.IOCs)

	node := output.ProcessTree.Nodes["uid:10001"]
	assert.Equal(t, "/usr/bin/curl", node.ExecutablePath)
	assert.Equal(t, "/tmp/work", node.Pwd)
	assert.NotNil(t, node.ExitTime)
}

func TestFromEventsParallelParity(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/sample.ndjson")
	require.NoError(t, err)

	seqEvents, err := input.ReadEventsWithOptions(bytes.NewReader(data), input.ParseOptions{Workers: 1})
	require.NoError(t, err)
	parEvents, err := input.ReadEventsWithOptions(bytes.NewReader(data), input.ParseOptions{Workers: 8})
	require.NoError(t, err)
	assert.Equal(t, seqEvents, parEvents)

	seqOpts := model.DefaultBuildOptions()
	seqOpts.Workers = 1
	parOpts := model.DefaultBuildOptions()
	parOpts.Workers = 8

	seqOutput := FromEvents(seqEvents, seqOpts)
	parOutput := FromEvents(parEvents, parOpts)

	seqOutput.Meta.GeneratedAt = time.Time{}
	parOutput.Meta.GeneratedAt = time.Time{}
	assert.Equal(t, seqOutput, parOutput)
}

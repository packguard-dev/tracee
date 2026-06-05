package input

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadEventsNDJSON(t *testing.T) {
	t.Parallel()

	events, err := ReadEvents(strings.NewReader(`{"timestamp":"2026-06-05T08:00:00Z","name":"sched_process_exec","workload":{"process":{"pid":10,"unique_id":99,"thread":{"name":"sh"}}},"data":[{"name":"argv","str_array":{"value":["sh","-c","id"]}}]}`))
	require.NoError(t, err)
	require.Len(t, events, 1)

	ev := events[0]
	assert.Equal(t, "sched_process_exec", ev.EventName)
	assert.Equal(t, "uid:99", ev.ProcessKey)
	assert.Equal(t, "sh", ev.ProcessName)
	assert.Equal(t, []string{"sh", "-c", "id"}, StringSliceFromField(ev.Fields, "argv"))
}

func TestReadEventsJSONArray(t *testing.T) {
	t.Parallel()

	events, err := ReadEvents(strings.NewReader(`[
		{"timestamp":1732454400123456789,"eventName":"security_inode_unlink","processId":22,"args":[{"name":"pathname","type":"string","value":"/tmp/x"}]}
	]`))
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "security_inode_unlink", events[0].EventName)
	assert.Equal(t, "/tmp/x", StringFromField(events[0].Fields, "pathname"))
}

func TestReadEventsFixture(t *testing.T) {
	t.Parallel()

	f, err := os.Open("../../testdata/sample.ndjson")
	require.NoError(t, err)
	defer f.Close()

	events, err := ReadEvents(f)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 8)
}

func TestReadEventsParallelParity(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/sample.ndjson")
	require.NoError(t, err)

	seq, err := ReadEventsWithOptions(bytes.NewReader(data), ParseOptions{Workers: 1})
	require.NoError(t, err)
	par, err := ReadEventsWithOptions(bytes.NewReader(data), ParseOptions{Workers: 8})
	require.NoError(t, err)
	assert.Equal(t, seq, par)
}

func TestReadEventsJSONArrayParallelParity(t *testing.T) {
	t.Parallel()

	raw := `[
		{"timestamp":1732454400123456789,"eventName":"security_inode_unlink","processId":22,"args":[{"name":"pathname","type":"string","value":"/tmp/x"}]}
	]`

	seq, err := ReadEventsWithOptions(strings.NewReader(raw), ParseOptions{Workers: 1})
	require.NoError(t, err)
	par, err := ReadEventsWithOptions(strings.NewReader(raw), ParseOptions{Workers: 4})
	require.NoError(t, err)
	assert.Equal(t, seq, par)
}

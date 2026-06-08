package mitm

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempJSONL(t, data)

	records, err := ParseFile(path)
	require.NoError(t, err)
	require.Len(t, records, 2)

	assert.Equal(t, "raw.githubusercontent.com", records[0].SNI)
	assert.Equal(t, int64(13287), records[0].ResponseBytes)
	assert.Contains(t, records[0].URL, "raw.githubusercontent.com")
}

func TestParseTimestampVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "no timezone",
			input: `{"timestamp":"2026-05-16T23:27:31.355084","destination":{"host":"1.2.3.4","port":443,"url":"https://example.com/"},"tls":{},"payload_sizes":{"response_bytes":10}}`,
		},
		{
			name:  "rfc3339",
			input: `{"timestamp":"2026-05-16T23:27:31.355084Z","destination":{"host":"1.2.3.4","port":443,"url":"https://example.com/"},"tls":{},"payload_sizes":{"response_bytes":10}}`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record, err := parseLine(tc.input)
			require.NoError(t, err)
			assert.False(t, record.Timestamp.IsZero())
			assert.Equal(t, int64(10), record.ResponseBytes)
		})
	}
}

func TestParseFileSkipsMalformedLines(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	content := append([]byte("not json\n"), data...)
	path := writeTempJSONL(t, content)

	records, err := ParseFile(path)
	require.NoError(t, err)
	assert.Len(t, records, 2)
}

func TestParseFileEmpty(t *testing.T) {
	t.Parallel()

	path := writeTempJSONL(t, []byte("\n\n"))
	_, err := ParseFile(path)
	require.Error(t, err)
}

func writeTempJSONL(t *testing.T, data []byte) string {
	t.Helper()
	path := t.TempDir() + "/mitm.jsonl"
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write temp jsonl: %v", err)
	}
	return path
}

func TestRecordsInWindow(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempJSONL(t, data)
	idx, err := NewIndex(path)
	require.NoError(t, err)

	center := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	inWindow := idx.RecordsInWindow(center, time.Minute)
	assert.Len(t, inWindow, 2)

	outside := idx.RecordsInWindow(time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC), time.Minute)
	assert.Empty(t, outside)
}

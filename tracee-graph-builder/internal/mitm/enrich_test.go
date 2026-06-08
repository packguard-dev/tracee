package mitm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestEnrichIOCsWithHints(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempJSONL(t, data)

	idx, err := NewIndex(path)
	require.NoError(t, err)

	iocTime := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	out := model.Output{
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: iocTime,
				EventName: "non_whitelisted_domain_connection",
				Fields: map[string]any{
					"domain": "raw.githubusercontent.com",
				},
			},
		},
	}

	enriched := EnrichIOCs(out, idx, EnrichOptions{
		Source: path,
		Window: time.Minute,
	})
	require.Len(t, enriched.IOCs, 1)
	require.NotNil(t, enriched.IOCs[0].Mitm)
	assert.Equal(t, model.PcapMatchModeHints, enriched.IOCs[0].Mitm.MatchMode)
	require.Len(t, enriched.IOCs[0].Mitm.Requests, 1)
	assert.Equal(t, "raw.githubusercontent.com", enriched.IOCs[0].Mitm.Requests[0].SNI)
	assert.Equal(t, int64(13287), enriched.IOCs[0].Mitm.Requests[0].ResponseBytes)
}

func TestEnrichIOCsWithoutHintsIncludesWindowRequests(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempJSONL(t, data)

	idx, err := NewIndex(path)
	require.NoError(t, err)

	iocTime := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	out := model.Output{
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: iocTime,
				EventName: "decoy_file_read",
				Fields:    map[string]any{"file_path": "/etc/shadow"},
			},
		},
	}

	enriched := EnrichIOCs(out, idx, EnrichOptions{
		Source: path,
		Window: time.Minute,
	})
	require.NotNil(t, enriched.IOCs[0].Mitm)
	assert.Equal(t, model.PcapMatchModeWindow, enriched.IOCs[0].Mitm.MatchMode)
	assert.Len(t, enriched.IOCs[0].Mitm.Requests, 2)
}

func TestEnrichIOCsOutsideWindowEmpty(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempJSONL(t, data)

	idx, err := NewIndex(path)
	require.NoError(t, err)

	out := model.Output{
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC),
				EventName: "decoy_file_read",
			},
		},
	}

	enriched := EnrichIOCs(out, idx, EnrichOptions{
		Source: path,
		Window: time.Minute,
	})
	assert.Nil(t, enriched.IOCs[0].Mitm)
}

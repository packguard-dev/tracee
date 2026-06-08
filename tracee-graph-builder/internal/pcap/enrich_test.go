package pcap

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
	path := writeTempPcap(t, data)
	exclude, err := DefaultExcludeCIDRs()
	require.NoError(t, err)

	idx, err := NewIndex(path, exclude)
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
		Source:  path,
		Window:  time.Minute,
		Exclude: exclude,
	})
	require.Len(t, enriched.IOCs, 1)
	require.NotNil(t, enriched.IOCs[0].Pcap)
	assert.Equal(t, model.PcapMatchModeHints, enriched.IOCs[0].Pcap.MatchMode)
	assert.NotEmpty(t, enriched.IOCs[0].Pcap.Indicators)
}

func TestEnrichIOCsWithoutHintsIncludesWindowFlows(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempPcap(t, data)
	exclude, err := DefaultExcludeCIDRs()
	require.NoError(t, err)

	idx, err := NewIndex(path, exclude)
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
		Source:  path,
		Window:  time.Minute,
		Exclude: exclude,
	})
	require.NotNil(t, enriched.IOCs[0].Pcap)
	assert.Equal(t, model.PcapMatchModeWindow, enriched.IOCs[0].Pcap.MatchMode)
	assert.NotEmpty(t, enriched.IOCs[0].Pcap.Indicators)
}

func TestEnrichIOCsOutsideWindowEmpty(t *testing.T) {
	t.Parallel()

	data, err := BuildTestFixture()
	require.NoError(t, err)
	path := writeTempPcap(t, data)
	exclude, err := DefaultExcludeCIDRs()
	require.NoError(t, err)

	idx, err := NewIndex(path, exclude)
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
		Source:  path,
		Window:  time.Minute,
		Exclude: exclude,
	})
	assert.Nil(t, enriched.IOCs[0].Pcap)
}

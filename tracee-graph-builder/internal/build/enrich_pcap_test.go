package build

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/pcap"
)

func TestEnrichFromPcapEndToEnd(t *testing.T) {
	t.Parallel()

	data, err := pcap.BuildTestFixture()
	require.NoError(t, err)
	path := t.TempDir() + "/fixture.pcapng"
	require.NoError(t, os.WriteFile(path, data, 0o644))

	out := model.Output{
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC),
				EventName: "non_whitelisted_domain_connection",
				Fields: map[string]any{
					"domain": "raw.githubusercontent.com",
				},
			},
		},
	}

	enriched, err := EnrichFromPcap(out, path, time.Minute, nil)
	require.NoError(t, err)
	require.NotNil(t, enriched.IOCs[0].Pcap)
	assert.Equal(t, path, enriched.Meta.PcapSource)
	assert.NotEmpty(t, enriched.IOCs[0].Pcap.Indicators)
}

func TestEnrichFromPcapNoOpWhenPathEmpty(t *testing.T) {
	t.Parallel()

	out := model.Output{IOCs: []model.IOCRecord{{ID: "ioc-1"}}}
	enriched, err := EnrichFromPcap(out, "", time.Minute, nil)
	require.NoError(t, err)
	assert.Equal(t, out, enriched)
}

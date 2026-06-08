package build

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/mitm"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestEnrichFromMitmEndToEnd(t *testing.T) {
	t.Parallel()

	data, err := mitm.BuildTestFixture()
	require.NoError(t, err)
	path := t.TempDir() + "/fixture.jsonl"
	require.NoError(t, os.WriteFile(path, data, 0o644))

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

	enriched, err := EnrichFromMitm(out, path, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, enriched.IOCs[0].Mitm)
	assert.Equal(t, path, enriched.Meta.MitmSource)
	assert.NotEmpty(t, enriched.IOCs[0].Mitm.Requests)
}

func TestEnrichFromMitmNoOpWhenPathEmpty(t *testing.T) {
	t.Parallel()

	out := model.Output{}
	enriched, err := EnrichFromMitm(out, "", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, out, enriched)
}

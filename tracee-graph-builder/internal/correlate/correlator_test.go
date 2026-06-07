                                                                                          package correlate

import (                                
	"testing"
	"time"
                                                    
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/graph"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)
                                                   
func TestCorrelatorLinksIOCFilesAndProcesses(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 8, 0, 6, 0, time.UTC)
	builder := graph.NewBuilder()
	builder.Ingest([]model.NormalizedEvent{
		{
			Index:      0,
			Timestamp:  now.Add(-4 * time.Second),
			EventName:  "security_file_open",
			ProcessKey: "uid:10001",
			ParentKey:  "uid:9001",
			Fields: map[string]any{
				"pathname": "/etc/shadow",
				"flags":    int32(0),
			},
		},
		{
			Index:      1,
			Timestamp:  now.Add(-2 * time.Second),
			EventName:  "file_modification",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"file_path": "/tmp/payload.bin",
			},
		},
		{
			Index:      2,
			Timestamp:  now,
			EventName:  "decoy_file_read",
			ProcessKey: "uid:10001",
			ParentKey:  "uid:9001",
			IsIOC:      true,
			Fields: map[string]any{
				"file_path": "/etc/shadow",
			},
		},
	})

	builder.Nodes()["uid:9001"] = model.ProcessNode{Key: "uid:9001", PID: 900}
	New(5 * time.Minute).Apply(builder)

	require.Len(t, builder.IOCs(), 1)
	ioc := builder.IOCs()[0]
	assert.Contains(t, ioc.RelatedProcessKeys, "uid:10001")
	assert.Contains(t, ioc.RelatedProcessKeys, "uid:9001")
	assert.NotEmpty(t, ioc.RelatedFileIDs)

	readFile := builder.Files().Read[0]
	assert.Contains(t, readFile.IOCIDs, ioc.ID)
}

func TestCorrelatorParallelParity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 8, 0, 6, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			Index:      0,
			Timestamp:  now.Add(-4 * time.Second),
			EventName:  "security_file_open",
			ProcessKey: "uid:10001",
			ParentKey:  "uid:9001",
			Fields: map[string]any{
				"pathname": "/etc/shadow",
				"flags":    int32(0),
			},
		},
		{
			Index:      1,
			Timestamp:  now.Add(-2 * time.Second),
			EventName:  "file_modification",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"file_path": "/tmp/payload.bin",
			},
		},
		{
			Index:      2,
			Timestamp:  now,
			EventName:  "decoy_file_read",
			ProcessKey: "uid:10001",
			ParentKey:  "uid:9001",
			IsIOC:      true,
			Fields: map[string]any{
				"file_path": "/etc/shadow",
			},
		},
	}

	seqBuilder := graph.NewBuilder()
	seqBuilder.IngestParallel(events, 1)
	seqBuilder.Nodes()["uid:9001"] = model.ProcessNode{Key: "uid:9001", PID: 900}
	New(5 * time.Minute).ApplyParallel(seqBuilder, 1)

	parBuilder := graph.NewBuilder()
	parBuilder.IngestParallel(events, 8)
	parBuilder.Nodes()["uid:9001"] = model.ProcessNode{Key: "uid:9001", PID: 900}
	New(5 * time.Minute).ApplyParallel(parBuilder, 8)

	require.Len(t, seqBuilder.IOCs(), 1)
	require.Len(t, parBuilder.IOCs(), 1)
	assert.Equal(t, seqBuilder.IOCs()[0], parBuilder.IOCs()[0])
	assert.Equal(t, seqBuilder.Files(), parBuilder.Files())
	assert.Equal(t, seqBuilder.Networks(), parBuilder.Networks())
}

func TestCorrelatorLinksIOCNetworkByDomain(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 7, 8, 29, 4, 0, time.UTC)
	builder := graph.NewBuilder()
	builder.Ingest([]model.NormalizedEvent{
		{
			Index:      0,
			Timestamp:  now.Add(-1 * time.Second),
			EventName:  "net_tcp_connect",
			ProcessKey: "uid:1029725475",
			Fields: map[string]any{
				"dst":      "185.199.108.133",
				"dst_port": int32(443),
				"dst_dns":  []string{"raw.githubusercontent.com"},
			},
		},
		{
			Index:      1,
			Timestamp:  now,
			EventName:  "non_whitelisted_domain_connection",
			ProcessKey: "uid:1029725475",
			IsIOC:      true,
			Fields: map[string]any{
				"domain": "raw.githubusercontent.com",
			},
		},
	})

	New(5 * time.Minute).Apply(builder)

	require.Len(t, builder.IOCs(), 1)
	ioc := builder.IOCs()[0]
	assert.NotEmpty(t, ioc.RelatedNetworkIDs)
	assert.Contains(t, ioc.RelatedNetworkIDs, "net-0")

	connect := builder.Networks().Connect[0]
	assert.Contains(t, connect.IOCIDs, ioc.ID)
}

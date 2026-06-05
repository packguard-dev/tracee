package graph

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestBuilderProcessAndFiles(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			Index:      0,
			Timestamp:  now,
			EventName:  "sched_process_fork",
			ProcessKey: "uid:10001",
			ParentKey:  "uid:9001",
			PID:        1000,
			Fields: map[string]any{
				"parent_pid": int32(900),
				"child_pid":  int32(1000),
			},
		},
		{
			Index:      1,
			Timestamp:  now.Add(time.Second),
			EventName:  "sched_process_exec",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"pathname": "/usr/bin/curl",
				"argv":     []string{"curl", "-s"},
				"pwd":      "/tmp",
			},
		},
		{
			Index:      2,
			Timestamp:  now.Add(2 * time.Second),
			EventName:  "security_file_open",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"pathname": "/etc/shadow",
				"flags":    int32(0),
			},
		},
		{
			Index:      3,
			Timestamp:  now.Add(3 * time.Second),
			EventName:  "file_modification",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"file_path": "/tmp/payload.bin",
			},
		},
		{
			Index:      4,
			Timestamp:  now.Add(4 * time.Second),
			EventName:  "security_inode_rename",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"old_path": "/tmp/payload.bin",
				"new_path": "/tmp/.hidden",
			},
		},
		{
			Index:      5,
			Timestamp:  now.Add(5 * time.Second),
			EventName:  "security_inode_unlink",
			ProcessKey: "uid:10001",
			Fields: map[string]any{
				"pathname": "/tmp/.hidden",
			},
		},
		{
			Index:      6,
			Timestamp:  now.Add(6 * time.Second),
			EventName:  "decoy_file_read",
			ProcessKey: "uid:10001",
			IsIOC:      true,
			Fields: map[string]any{
				"file_path": "/etc/shadow",
			},
		},
	}

	builder := NewBuilder()
	builder.Ingest(events)

	node, ok := builder.Nodes()["uid:10001"]
	require.True(t, ok)
	require.NotEmpty(t, node.Key)
	assert.Equal(t, "/usr/bin/curl", node.ExecutablePath)
	assert.Equal(t, "curl -s", node.CommandLine)
	assert.Equal(t, "/tmp", node.Pwd)

	assert.Len(t, builder.Files().Read, 1)
	assert.Len(t, builder.Files().Write, 1)
	assert.Len(t, builder.Files().Rename, 1)
	assert.Len(t, builder.Files().Delete, 1)
	assert.Len(t, builder.IOCs(), 1)
}

func TestBuilderWhitelistExcludesNoisyPathsAndCommands(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			Index:      0,
			Timestamp:  now,
			EventName:  "sched_process_exec",
			ProcessKey: "uid:npm",
			Fields: map[string]any{
				"pathname": "/usr/bin/npm",
				"argv":     []string{"npm", "install", "lodash"},
			},
		},
		{
			Index:      1,
			Timestamp:  now.Add(time.Second),
			EventName:  "security_file_open",
			ProcessKey: "uid:npm",
			Fields: map[string]any{
				"pathname": "/usr/lib/node_modules/foo/index.js",
				"flags":    int32(0),
			},
		},
		{
			Index:      2,
			Timestamp:  now.Add(2 * time.Second),
			EventName:  "sched_process_exec",
			ProcessKey: "uid:curl",
			Fields: map[string]any{
				"pathname": "/usr/bin/curl",
				"argv":     []string{"curl", "-s"},
			},
		},
		{
			Index:      3,
			Timestamp:  now.Add(3 * time.Second),
			EventName:  "security_file_open",
			ProcessKey: "uid:curl",
			Fields: map[string]any{
				"pathname": "/etc/shadow",
				"flags":    int32(0),
			},
		},
	}

	builder := NewBuilder()
	builder.Ingest(events)

	assert.Len(t, builder.Files().Read, 1)
	assert.Equal(t, "/etc/shadow", builder.Files().Read[0].Path)
}

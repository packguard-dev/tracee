package filter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestDedupFileEvents_DropsWithinWindow(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			EventName:  "security_file_open",
			ProcessKey: "uid:1",
			Timestamp:  base,
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
		{
			EventName:  "security_file_open",
			ProcessKey: "uid:1",
			Timestamp:  base.Add(2 * time.Minute),
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
	}

	out := DedupFileEvents(events, 5*time.Minute)
	if assert.Len(t, out, 1) {
		assert.Equal(t, base, out[0].Timestamp)
	}
}

func TestDedupFileEvents_KeepsOutsideWindow(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			EventName:  "file_modification",
			ProcessKey: "uid:1",
			Timestamp:  base,
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
		{
			EventName:  "file_modification",
			ProcessKey: "uid:1",
			Timestamp:  base.Add(6 * time.Minute),
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
	}

	out := DedupFileEvents(events, 5*time.Minute)
	assert.Len(t, out, 2)
}

func TestDedupFileEvents_DoesNotCrossProcessKey(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			EventName:  "security_inode_unlink",
			ProcessKey: "uid:1",
			Timestamp:  base,
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
		{
			EventName:  "security_inode_unlink",
			ProcessKey: "uid:2",
			Timestamp:  base.Add(2 * time.Minute),
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
	}

	out := DedupFileEvents(events, 5*time.Minute)
	assert.Len(t, out, 2)
}

func TestDedupFileEvents_PreservesEventsMissingKeyParts(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			EventName:  "security_inode_rename",
			ProcessKey: "uid:1",
			Timestamp:  base,
			Fields: map[string]any{
				"old_path": "/tmp/a",
				"new_path": "/tmp/b",
			},
		},
		{
			EventName:  "security_inode_rename",
			ProcessKey: "uid:1",
			Timestamp:  base.Add(2 * time.Minute),
			Fields: map[string]any{
				"old_path": "/tmp/a",
				"new_path": "/tmp/b",
			},
		},
	}

	out := DedupFileEvents(events, 5*time.Minute)
	assert.Len(t, out, 2)
}

func TestDedupFileEvents_OnlyAppliesToSelectedEvents(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			EventName:  "vfs_write",
			ProcessKey: "uid:1",
			Timestamp:  base,
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
		{
			EventName:  "vfs_write",
			ProcessKey: "uid:1",
			Timestamp:  base.Add(2 * time.Minute),
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
	}

	out := DedupFileEvents(events, 5*time.Minute)
	assert.Len(t, out, 2)
}

func TestDedupFileEvents_DoesNotDedupAcrossEventTypes(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	events := []model.NormalizedEvent{
		{
			EventName:  "file_modification",
			ProcessKey: "uid:1",
			Timestamp:  base,
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
		{
			EventName:  "security_inode_unlink",
			ProcessKey: "uid:1",
			Timestamp:  base.Add(2 * time.Minute),
			Fields: map[string]any{
				"dev":   uint32(1),
				"inode": uint64(2),
			},
		},
	}

	out := DedupFileEvents(events, 5*time.Minute)
	assert.Len(t, out, 2)
}


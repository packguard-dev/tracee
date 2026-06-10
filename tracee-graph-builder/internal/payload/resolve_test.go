package payload

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestResolvePathInterpreterScript(t *testing.T) {
	t.Parallel()

	node := model.ProcessNode{
		ExecutablePath: "/usr/bin/python3.10",
		Argv:           []string{"python3", "/app/AppUpdates/updater.py"},
		Pwd:            "/app",
	}
	assert.Equal(t, "/app/AppUpdates/updater.py", ResolvePath(node))
}

func TestResolvePathDirectBinary(t *testing.T) {
	t.Parallel()

	node := model.ProcessNode{
		ExecutablePath: "/app/AppUpdates/updater",
		Argv:           []string{"/app/AppUpdates/updater", "skip"},
		Pwd:            "/app",
	}
	assert.Equal(t, "/app/AppUpdates/updater", ResolvePath(node))
}

func TestResolvePathRelativeScriptWithPwd(t *testing.T) {
	t.Parallel()

	node := model.ProcessNode{
		ExecutablePath: "/usr/bin/node",
		Argv:           []string{"node", "app.js"},
		Pwd:            "/app",
	}
	assert.Equal(t, "/app/app.js", ResolvePath(node))
}

func TestResolveFileIdentityPriority(t *testing.T) {
	t.Parallel()

	index := map[string][]model.FileIdentityRef{
		"/app/AppUpdates/updater.py": {
			{Inode: 354727, Ctime: 100, Source: "security_file_open"},
			{Inode: 354727, Ctime: 200, Source: "file_modification"},
		},
	}

	refs := ResolveFileIdentity(index, "/app/AppUpdates/updater.py")
	assert.Len(t, refs, 2)
	assert.Equal(t, uint64(200), refs[0].Ctime)
	assert.Equal(t, "file_modification", refs[0].Source)
}

func TestResolveInodeCandidatesDedupesByInode(t *testing.T) {
	t.Parallel()

	index := map[string][]model.FileIdentityRef{
		"/app/AppUpdates/updater.py": {
			{Inode: 354727, Ctime: 100, Source: "security_file_open"},
			{Inode: 354727, Ctime: 200, Source: "file_modification"},
			{Inode: 354728, Ctime: 300, Source: "file_modification"},
		},
	}

	inodes := ResolveInodeCandidates(index, "/app/AppUpdates/updater.py")
	assert.Equal(t, []uint64{354727, 354728}, inodes)
}

func TestEnrichIOCWithoutPathIndex(t *testing.T) {
	t.Parallel()

	ioc := model.IOCRecord{ProcessKey: "uid:1"}
	nodes := map[string]model.ProcessNode{
		"uid:1": {
			Key:            "uid:1",
			ExecutablePath: "/app/AppUpdates/updater",
		},
	}

	enriched := EnrichIOC(ioc, nodes, nil)
	assert.NotNil(t, enriched.Payload)
	assert.Equal(t, "/app/AppUpdates/updater", enriched.Payload.Path)
	assert.Equal(t, model.PayloadStatusNotInEvents, enriched.Payload.Status)
}

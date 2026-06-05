package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultWhitelistPathPrefixes(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.IsPathExcluded("/usr/lib/x86_64-linux-gnu/libc.so.6"))
	assert.True(t, wl.IsPathExcluded("/lib64/ld-linux-x86-64.so.2"))
	assert.False(t, wl.IsPathExcluded("/etc/shadow"))
}

func TestDefaultWhitelistPathExact(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.IsPathExcluded("/etc/ld.so.cache"))
	assert.False(t, wl.IsPathExcluded("/etc/ld.so.cache.d"))
}

func TestDefaultWhitelistPathGlob(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.IsPathExcluded("/tmp/archive-backup.tgz"))
	assert.False(t, wl.IsPathExcluded("/tmp/archive-backup.tar"))
}

func TestDefaultWhitelistCommands(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.IsCommandExcluded("/usr/bin/npm", "npm install lodash", []string{"npm", "install", "lodash"}))
	assert.True(t, wl.IsCommandExcluded(
		"/usr/bin/node",
		"/usr/bin/node /usr/bin/npm install lodash",
		[]string{"/usr/bin/node", "/usr/bin/npm", "install", "lodash"},
	))
	assert.True(t, wl.IsCommandExcluded(
		"/app/.vscode/vscode-linux-x64/bin/code",
		"code --wait",
		[]string{"code", "--wait"},
	))
	assert.False(t, wl.IsCommandExcluded("/usr/bin/curl", "curl -s http://example.com", []string{"curl", "-s", "http://example.com"}))
}

func TestShouldExcludeFileRecord(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.ShouldExcludeFileRecord("/usr/lib/python3.10/site-packages/pkg.py", "", ""))
	assert.False(t, wl.ShouldExcludeFileRecord("/tmp/payload.bin", "", ""))
	assert.True(t, wl.ShouldExcludeFileRecord("/tmp/out", "/usr/lib/foo", "/tmp/out"))
}

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

func TestDefaultWhitelistDomains(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.IsDomainExcluded("registry.npmjs.org"))
	assert.True(t, wl.IsDomainExcluded("files.pythonhosted.org"))
	assert.True(t, wl.IsDomainExcluded("marketplace.visualstudio.com"))
	assert.False(t, wl.IsDomainExcluded("raw.githubusercontent.com"))
	assert.False(t, wl.IsDomainExcluded("attacker.com"))
}

func TestShouldExcludeNetworkRecord(t *testing.T) {
	t.Parallel()

	wl := DefaultWhitelist()
	assert.True(t, wl.ShouldExcludeNetworkRecord([]string{"registry.npmjs.org"}))
	assert.False(t, wl.ShouldExcludeNetworkRecord([]string{"raw.githubusercontent.com"}))
	assert.False(t, wl.ShouldExcludeNetworkRecord(nil))
	assert.False(t, wl.ShouldExcludeNetworkRecord([]string{"registry.npmjs.org", "attacker.com"}))
}

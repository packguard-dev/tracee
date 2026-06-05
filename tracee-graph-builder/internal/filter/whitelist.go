package filter

import (
	"path/filepath"
	"strings"
)

// Whitelist excludes noisy file paths and commands from graph output.
type Whitelist struct {
	pathPrefixes []string
	pathExact    map[string]struct{}
	pathGlobs    []string
	commandGlobs []string
}

// DefaultWhitelist returns the built-in path and command exclusions.
func DefaultWhitelist() Whitelist {
	return Whitelist{
		pathPrefixes: []string{
			"/usr/lib/",
			"/usr/lib64/",
			"/lib/",
			"/lib64/",
			"/usr/share/zoneinfo/",
			"/usr/lib/locale/",
			"/usr/local/lib/python",
			"/usr/lib/python",
			"/usr/lib/python3",
			"/usr/lib/python3.10",
			"/usr/lib/python3.11",
			"/usr/lib/x86_64-linux-gnu/",
			"/usr/lib/aarch64-linux-gnu/",
			"/run/containers/",
		},
		pathExact: map[string]struct{}{
			"/etc/ld.so.cache": {},
			"/execution.log": {},
			"/execution-log.json": {},
		},
		pathGlobs: []string{
			"/tmp/archive*.tgz",
		},
		commandGlobs: []string{
			"/app/.vscode/*",
			"/app/.vscode/vscode-linux-x64/bin/code*",
			"/app/.vscode/vscode-linux-x64/code*",
			"/usr/bin/node /usr/bin/npm install *",
			"/usr/bin/node /usr/local/bin/analyze*",
			"/usr/bin/node /usr/local/bin/analyze-node.js *",
			"/usr/bin/npm",
			"/usr/bin/npm init --force",
			"/usr/bin/npm install *",
		},
	}
}

// IsPathExcluded reports whether a file path matches the path whitelist.
func (w Whitelist) IsPathExcluded(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if _, ok := w.pathExact[path]; ok {
		return true
	}
	for _, prefix := range w.pathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for _, pattern := range w.pathGlobs {
		if globMatch(pattern, path) {
			return true
		}
	}
	return false
}

// IsCommandExcluded reports whether a process command matches the command whitelist.
func (w Whitelist) IsCommandExcluded(executablePath, commandLine string, argv []string) bool {
	candidates := commandCandidates(executablePath, commandLine, argv)
	for _, pattern := range w.commandGlobs {
		for _, candidate := range candidates {
			if globMatch(pattern, candidate) {
				return true
			}
		}
	}
	return false
}

// ShouldExcludeFileRecord reports whether a file record should be omitted.
func (w Whitelist) ShouldExcludeFileRecord(path, oldPath, newPath string) bool {
	if w.IsPathExcluded(path) {
		return true
	}
	if w.IsPathExcluded(oldPath) {
		return true
	}
	if w.IsPathExcluded(newPath) {
		return true
	}
	return false
}

func commandCandidates(executablePath, commandLine string, argv []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 4)

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}

	add(executablePath)
	add(commandLine)
	if len(argv) > 0 {
		add(strings.Join(argv, " "))
	}
	if executablePath != "" && len(argv) > 0 {
		add(strings.TrimSpace(executablePath + " " + strings.Join(argv, " ")))
	}
	return out
}

func globMatch(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	return err == nil && matched
}

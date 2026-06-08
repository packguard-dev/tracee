package detectors

import (
	"strings"

	enry "github.com/go-enry/go-enry/v2"
)

// knownScriptLanguages maps Linguist language names (returned by go-enry) to the
// normalised file_type labels used throughout our detector output.  Only script
// and interpreted languages are listed — compiled languages like Go or Rust are
// intentionally excluded because they are caught by the binary-header detectors
// (ELF / PE / Mach-O).
var knownScriptLanguages = map[string]string{
	"Python":     "python_script",
	"JavaScript": "javascript_script",
	"TypeScript": "typescript_script",
	"Shell":      "bash_script",
	"Bash":       "bash_script",
	"Ruby":       "ruby_script",
	"Perl":       "perl_script",
	"PowerShell": "powershell_script",
	"PHP":        "php_script",
	"Hack":       "php_script", // go-enry classifies .php as Hack (PHP superset)
	"Lua":        "lua_script",
}

// ignoredLanguages are Linguist language names that go-enry may detect but
// which are NOT script/interpreted languages. Matching these would cause false
// positives (e.g. plain text files, markdown docs, config files).
var ignoredLanguages = map[string]bool{
	"Text":         true,
	"Markdown":     true,
	"JSON":         true,
	"XML":          true,
	"YAML":         true,
	"TOML":         true,
	"INI":          true,
	"CSV":          true,
	"HTML":         true,
	"CSS":          true,
	"SVG":          true,
	"Dockerfile":   true,
	"Makefile":     true,
	"CMake":        true,
	"Diff":         true,
}

// classifyByEnry uses the go-enry library (a Go port of GitHub Linguist) to
// identify the programming language of a file by analysing its filename and,
// optionally, its content bytes.
//
// Returns:
//   - fileType: normalised label (e.g. "python_script") or "" if unrecognised
//   - language: raw language name from Linguist (e.g. "Python") or ""
//   - ok:       true when the file was classified as a known script language
func classifyByEnry(filename string, content []byte) (fileType string, language string, ok bool) {
	lang := enry.GetLanguage(filename, content)
	if lang == "" {
		return "", "", false
	}

	// Skip non-script languages to avoid false positives
	if ignoredLanguages[lang] {
		return "", "", false
	}

	if ft, found := knownScriptLanguages[lang]; found {
		return ft, lang, true
	}

	// For languages not in our explicit map, produce a generic label so we
	// still record *what* was detected without silently discarding it.
	return strings.ToLower(lang) + "_script", lang, true
}

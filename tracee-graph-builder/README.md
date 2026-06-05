# tracee-graph-builder

Offline tool that reads Tracee JSON events and emits process tree, file
activity, and IOC correlation graphs.

## Purpose

Given Tracee event captures, this tool helps answer:

- Which process tree produced an IOC event?
- Which files were read, written, deleted, or renamed around that activity?
- How are IOC events linked to process lineage and file operations?

## Input

Supports:

- NDJSON (one event per line), as produced by `tracee --output json`
- JSON array files

Supported event families:

- Process lifecycle: `sched_process_fork`, `sched_process_exec`, `sched_process_exit`
- File activity: `security_file_open`, `file_modification`, `security_inode_unlink`, `security_inode_rename`
- IOC examples: `decoy_file_read`, `dns_exfiltration`, `non_whitelisted_domain_connection`, `sensitive_read_dns_exfiltration`, `fileless_execution`, `hidden_file_created`

Current `v1beta1` JSON is the primary format. Legacy flat JSON (`processId`,
`eventName`, `args`) is also accepted.

## Output

Two output formats are supported via `-format`:

- `json` (default): one JSON document with `process_tree`, `files`, and `iocs`
- `table`: human-readable report grouped per IOC with process trees and file activity

JSON fields:

- `process_tree`: process nodes, parent links, exec metadata, lifecycle timestamps
- `files`: grouped records under `READ`, `WRITE`, `DELETE`, `RENAME`
- `iocs`: IOC events with related process keys, file IDs, and relation reasons

Table sections per IOC:

- `IOCs`: event name, timestamp, process, and key IOC fields
- `Process trees`: ancestry and descendants related to the IOC
- `Files`: related `READ`, `WRITE`, `DELETE`, and `RENAME` activity

## Usage

```sh
cd tracee-graph-builder
go test ./...
go run ./cmd/tracee-graph-builder -input testdata/sample.ndjson -output /tmp/graphs.json
```

Flags:

- `-input`: required input JSON path
- `-output`: output path (`-` or empty writes to stdout)
- `-format`: `json` or `table` (default: `json`)
- `-window-sec`: IOC correlation window (default: 300)
- `-workers`: worker count for parallel parse/build/correlate stages (default: 0, uses GOMAXPROCS)

## Examples

JSON output to file:

```sh
go run ./cmd/tracee-graph-builder \
  -input testdata/sample.ndjson \
  -format json \
  -output /tmp/tracee-graphs.json \
  -window-sec 300
```

Table output for quick triage:

```sh
go run ./cmd/tracee-graph-builder \
  -input testdata/sample3.ndjson \
  -format table > /tmp/tracee-graph.txt
```

## IOC Relation Logic

Version 1 links IOCs using:

- Direct process match
- Ancestor chain
- Descendant process window
- Direct file fields (`file_path`, `pathname`, `script_path`, etc.)
- `detected_from` file fields
- Family process file activity within the correlation window
- Rename chain links between old and new paths

## Noise filtering

Built-in path and command whitelists exclude common library paths and dev-tool
commands (npm, VS Code, Python site-packages, and similar) from file activity
output. Process nodes are still recorded; file events on whitelisted paths or
from whitelisted commands are omitted.

## Limitations

- Standalone module; does not execute Tracee or load eBPF programs.
- Open flag classification ignores ambiguous opens.
- Process keys fall back to PID-based identity when `unique_id` is missing.
- DNS IOC events may not map to files directly; they map to process lineage and nearby file activity.

## Development Rules

See [RULES.md](RULES.md).
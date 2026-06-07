# tracee-graph-builder

Offline tool that reads Tracee JSON events and emits process tree, file
activity, network activity, and IOC correlation graphs.

## Purpose

Given Tracee event captures, this tool helps answer:

- Which process tree produced an IOC event?
- Which files were read, written, deleted, or renamed around that activity?
- Which network connections occurred around that activity?
- How are IOC events linked to process lineage, file operations, and network activity?

## Input

Supports:

- NDJSON (one event per line), as produced by `tracee --output json`
- JSON array files
- Optional `artifacts.zip` from Tracee forensics (`--artifacts file-write`)

Supported event families:

- Process lifecycle: `sched_process_fork`, `sched_process_exec`, `sched_process_exit`
- File activity: `security_file_open`, `file_modification`, `security_inode_unlink`, `security_inode_rename`
- Network activity: `net_tcp_connect`
- IOC examples: `decoy_file_read`, `dns_exfiltration`, `non_whitelisted_domain_connection`, `sensitive_read_dns_exfiltration`, `fileless_execution`, `hidden_file_created`

Current `v1beta1` JSON is the primary format. Legacy flat JSON (`processId`,
`eventName`, `args`) is also accepted.

## Output

Two output formats are supported via `-format`:

- `json` (default): one JSON document with `process_tree`, `files`, `networks`, and `iocs`
- `table`: human-readable report grouped per IOC with process trees, file activity, and network activity

JSON fields:

- `process_tree`: process nodes, parent links, exec metadata, lifecycle timestamps
- `files`: grouped records under `READ`, `WRITE`, `DELETE`, `RENAME`
- `networks`: grouped records under `CONNECT`
- `iocs`: IOC events with related process keys, file IDs, network IDs, relation reasons, and optional `payload` (path, dev, inode, sha256)

Table sections per IOC:

- `IOCs`: event name, timestamp, process, key IOC fields, and payload path/dev/inode/sha256 when available
- `Process trees`: ancestry and descendants related to the IOC
- `Files`: related `READ`, `WRITE`, `DELETE`, and `RENAME` activity
- `Network`: related `CONNECT` activity

## Usage

```sh
cd tracee-graph-builder
go test ./...
go run ./cmd/tracee-graph-builder -input testdata/sample.ndjson -output /tmp/graphs.json
```

Flags:

- `-input`: required input JSON path
- `-artifacts`: optional path to `artifacts.zip` from Tracee `--artifacts file-write`
- `-output`: output path (`-` or empty writes to stdout)
- `-format`: `json` or `table` (default: `json`)
- `-window-sec`: IOC correlation window (default: 300)
- `-workers`: worker count for parallel parse/build/correlate stages (default: 0, uses GOMAXPROCS)

## Examples

JSON output to file:

```sh
go run ./cmd/tracee-graph-builder \
  -input testdata/sample1.ndjson \
  -format json \
  -output /tmp/tracee-graphs.json \
  -window-sec 300
```

Table output for quick triage:

```sh
go run ./cmd/tracee-graph-builder \
  -input testdata/sample1.ndjson \
  -format table > /tmp/tracee-graph.txt
```

Payload enrichment with artifacts zip:

```sh
go run ./cmd/tracee-graph-builder \
  -input events.ndjson \
  -artifacts artifacts.zip \
  -format table
```

The zip layout matches Tracee forensics output, for example:

```txt
run/artifacts/out/<container_id>/write.dev-<dev>.inode-<inode>
```

For each IOC, the tool resolves the payload file from the IOC process
(interpreter script path when applicable, otherwise the executable path),
looks up `dev` and `inode` from file/exec events, and when `-artifacts` is
set reads the matching write artifact and adds a SHA256 hash to the report.

Network fixture:

```sh
go run ./cmd/tracee-graph-builder \
  -input testdata/sample_net.ndjson \
  -format table
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
- Direct network fields (`domain`, `query`, `base_domain`, `dst`, `dst_port`)
- `detected_from` network fields and packet metadata
- Family process network activity within the correlation window

## Noise filtering

Built-in path and command whitelists exclude common library paths and dev-tool
commands (npm, VS Code, Python site-packages, and similar) from file activity
output. A built-in DNS domain whitelist excludes common package and dev-tool
destinations (`npmjs.org`, `pypi.org`, `pythonhosted.org`, `nodejs.org`,
`visualstudio.com`, `vscode-cdn.net`, `googleapis.com`, and subdomains) from
network activity output. Process nodes are still recorded; file events on
whitelisted paths or from whitelisted commands, and network connects to
whitelisted destinations, are omitted.

## Event deduplication

File activity events are deduplicated within a 5-minute window by
`(event, process, dev, inode)`.

`net_tcp_connect` events are deduplicated within a 30-second window by
`(net_tcp_connect, process, dst_dns, dst_port)`.

## Limitations

- Standalone module; does not execute Tracee or load eBPF programs.
- Payload is resolved from the IOC process only (not ancestors/descendants).
- SHA256 requires the payload file to be present in the artifacts zip.
- Relative script paths depend on `pwd` from `sched_process_exec`.
- Open flag classification ignores ambiguous opens.
- Process keys fall back to PID-based identity when `unique_id` is missing.
- DNS IOC events may not map to files directly; they map to process lineage, nearby file activity, and matching network connections.

## Development Rules

See [RULES.md](RULES.md).

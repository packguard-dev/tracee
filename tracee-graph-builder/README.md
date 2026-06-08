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
- Optional pcap/pcapng from tcpdump for IOC network enrichment
- Optional `mitm_proxy.jsonl` from mitmproxy for IOC HTTP enrichment

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
- `iocs`: IOC events with related process keys, file IDs, network IDs, relation reasons, optional `payload` (path, dev, inode, sha256), optional `pcap` external indicators (ip, port, protocol, domain), and optional `mitm` HTTP requests (url, host, sni, response_bytes, timestamp)

Table sections per IOC:

- `IOCs`: event name, timestamp, process, key IOC fields, and payload path/dev/inode/sha256 when available
- `Process trees`: ancestry and descendants related to the IOC
- `Files`: related `READ`, `WRITE`, `DELETE`, and `RENAME` activity
- `Network`: related `CONNECT` activity
- `External indicators (pcap)`: outsider IP, port, protocol, and DNS domain from optional PCAP enrichment
- `External requests (mitm)`: URL, host, SNI, and response size from optional MITM proxy enrichment

## Usage

```sh
cd tracee-graph-builder
go test ./...
go run ./cmd/tracee-graph-builder -input testdata/sample.ndjson -output /tmp/graphs.json
```

Flags:

- `-input`: required input JSON path
- `-artifacts`: optional path to `artifacts.zip` from Tracee `--artifacts file-write`
- `-pcap`: optional path to a tcpdump pcap/pcapng file for external indicator enrichment
- `-mitm`: optional path to `mitm_proxy.jsonl` for HTTP request enrichment
- `-exclude-cidr`: additional internal CIDR to exclude from PCAP outsider reports (repeatable; defaults include `172.16.17.0/24`, `10.68.0.0/14`, `34.118.224.0/20`, loopback, and link-local ranges)
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

PCAP enrichment with a tcpdump capture:

```sh
go run ./cmd/tracee-graph-builder \
  -input events.ndjson \
  -pcap /path/to/capture.pcap \
  -window-sec 300 \
  -format table
```

tcpdump capture example:

```sh
tcpdump -i any -w capture.pcap host 10.68.0.5
```

For each IOC, PCAP enrichment scans packets within the correlation window. When IOC fields include domain or IP hints, matching external flows are reported. Otherwise all external flows in the window are included. Internal and GKE pod/service ranges are excluded by default. Standard tcpdump link types are supported (Ethernet, Linux cooked capture, and similar).

MITM proxy enrichment with `mitm_proxy.jsonl`:

```sh
go run ./cmd/tracee-graph-builder \
  -input events.ndjson \
  -mitm mitm_proxy.jsonl \
  -window-sec 300 \
  -format table
```

The JSONL file is produced by the mitmproxy addon in `mitm_proxy.py`. Each line
records one HTTP response with `destination.url`, `destination.host`,
`tls.sni`, `payload_sizes.response_bytes`, and `timestamp`. For each IOC,
enrichment scans requests within the correlation window. When IOC fields
include domain or IP hints, matching requests are reported. Otherwise all
requests in the window are included.

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
- PCAP enrichment reads a single tcpdump pcap/pcapng file (not a directory of split captures).
- MITM enrichment reads a single `mitm_proxy.jsonl` file (not a directory).
- Relative script paths depend on `pwd` from `sched_process_exec`.
- Open flag classification ignores ambiguous opens.
- Process keys fall back to PID-based identity when `unique_id` is missing.
- DNS IOC events may not map to files directly; they map to process lineage, nearby file activity, and matching network connections.

## Development Rules

See [RULES.md](RULES.md).

package input

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/parallel"
)

type rawEvent struct {
	Timestamp    json.RawMessage `json:"timestamp"`
	ID           json.RawMessage `json:"id"`
	Name         string          `json:"name"`
	EventName    string          `json:"eventName"`
	Workload     *rawWorkload    `json:"workload"`
	Data         []rawEventValue `json:"data"`
	Args         []rawEventValue `json:"args"`
	DetectedFrom *rawDetected    `json:"detected_from"`

	ProcessID           int    `json:"processId"`
	ParentProcessID     int    `json:"parentProcessId"`
	HostProcessID       int    `json:"hostProcessId"`
	ProcessName         string `json:"processName"`
	ProcessEntityID     uint32 `json:"processEntityId"`
	ParentEntityID      uint32 `json:"parentEntityId"`
	ThreadStartTime     int64  `json:"threadStartTime"`
}

type rawWorkload struct {
	Process   *rawProcess   `json:"process"`
	Container *rawContainer `json:"container"`
}

type rawContainer struct {
	ID string `json:"id"`
}

type rawProcess struct {
	UniqueID   uint32        `json:"unique_id"`
	PID        uint32        `json:"pid"`
	HostPID    uint32        `json:"host_pid"`
	Executable *rawExecPath  `json:"executable"`
	Thread     *rawThread    `json:"thread"`
	Ancestors  []rawProcess  `json:"ancestors"`
}

type rawExecPath struct {
	Path string `json:"path"`
}

type rawThread struct {
	Name      string          `json:"name"`
	UniqueID  uint32          `json:"unique_id"`
	StartTime json.RawMessage `json:"start_time"`
}

type rawDetected struct {
	ID   uint32          `json:"id"`
	Name string          `json:"name"`
	Data []rawEventValue `json:"data"`
}

type rawEventValue struct {
	Name       string          `json:"name"`
	Value      json.RawMessage `json:"value"`
	Str        string          `json:"str"`
	Int32      *int32          `json:"int32"`
	Int64      json.RawMessage `json:"int64"`
	UInt32     *uint32         `json:"u_int32"`
	UInt64     json.RawMessage `json:"u_int64"`
	Bool       *bool           `json:"bool"`
	StrArray   *rawStrArray    `json:"str_array"`
	Int32Array *rawInt32Array  `json:"int32_array"`
}

type rawStrArray struct {
	Value []string `json:"value"`
}

type rawInt32Array struct {
	Value []int32 `json:"value"`
}

// ParseOptions configures parallel JSON ingestion.
type ParseOptions struct {
	Workers int // 0 uses GOMAXPROCS
}

// ReadEvents parses NDJSON or a JSON array of Tracee events.
func ReadEvents(r io.Reader) ([]model.NormalizedEvent, error) {
	return ReadEventsWithOptions(r, ParseOptions{})
}

// ReadEventsWithOptions parses Tracee events using a worker pool when Workers != 1.
func ReadEventsWithOptions(r io.Reader, opts ParseOptions) ([]model.NormalizedEvent, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("input is empty")
	}

	workers := parallel.WorkerCount(opts.Workers)
	if workers == 1 {
		return readEventsSequential(trimmed)
	}

	if trimmed[0] == '[' {
		return readEventsJSONArrayParallel(trimmed, workers)
	}
	return readEventsNDJSONParallel(trimmed, workers)
}

func readEventsSequential(trimmed []byte) ([]model.NormalizedEvent, error) {
	rawEvents, err := decodeRawEvents(trimmed)
	if err != nil {
		return nil, err
	}

	out := make([]model.NormalizedEvent, len(rawEvents))
	for i, ev := range rawEvents {
		normalized, err := normalizeEvent(ev, i)
		if err != nil {
			return nil, fmt.Errorf("normalize event %d: %w", i, err)
		}
		out[i] = normalized
	}
	return out, nil
}

func decodeRawEvents(trimmed []byte) ([]rawEvent, error) {
	if trimmed[0] == '[' {
		var events []rawEvent
		if err := json.Unmarshal(trimmed, &events); err != nil {
			return nil, fmt.Errorf("parse json array: %w", err)
		}
		return events, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	events := make([]rawEvent, 0)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev rawEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse line %d: %w", lineNo, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan input: %w", err)
	}
	return events, nil
}

func readEventsJSONArrayParallel(trimmed []byte, workers int) ([]model.NormalizedEvent, error) {
	var rawMessages []json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMessages); err != nil {
		return nil, fmt.Errorf("parse json array: %w", err)
	}
	return decodeAndNormalizeParallel(rawMessages, workers)
}

func readEventsNDJSONParallel(trimmed []byte, workers int) ([]model.NormalizedEvent, error) {
	lines, err := collectNDJSONLines(trimmed)
	if err != nil {
		return nil, err
	}

	rawMessages := make([]json.RawMessage, len(lines))
	for i, line := range lines {
		rawMessages[i] = json.RawMessage(line)
	}
	return decodeAndNormalizeParallel(rawMessages, workers)
}

func collectNDJSONLines(trimmed []byte) ([][]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	lines := make([][]byte, 0)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		copied := make([]byte, len(line))
		copy(copied, line)
		lines = append(lines, copied)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan input: %w", err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("input is empty")
	}
	return lines, nil
}

func decodeAndNormalizeParallel(rawMessages []json.RawMessage, workers int) ([]model.NormalizedEvent, error) {
	n := len(rawMessages)
	out := make([]model.NormalizedEvent, n)

	err := parallel.Run(context.Background(), workers, n, func(i int) error {
		var ev rawEvent
		if err := json.Unmarshal(rawMessages[i], &ev); err != nil {
			return fmt.Errorf("parse event %d: %w", i, err)
		}

		normalized, err := normalizeEvent(ev, i)
		if err != nil {
			return fmt.Errorf("normalize event %d: %w", i, err)
		}
		out[i] = normalized
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeEvent(ev rawEvent, index int) (model.NormalizedEvent, error) {
	name := strings.TrimSpace(ev.Name)
	if name == "" {
		name = strings.TrimSpace(ev.EventName)
	}
	if name == "" {
		name = parseNameFromID(ev.ID)
	}

	ts, err := parseTimestamp(ev.Timestamp)
	if err != nil {
		return model.NormalizedEvent{}, err
	}

	fields := mergeFields(ev.Data, ev.Args)
	processKey, parentKey, pid, hostPID, parentPID, processName, execPath, containerID, ancestors :=
		extractProcessContext(ev, fields, ts)

	detectedFrom := parseDetectedFrom(ev.DetectedFrom)
	if detectedFrom != nil {
		for k, v := range detectedFrom.Data {
			if _, exists := fields[k]; !exists {
				fields[k] = v
			}
		}
	}

	_, isIOC := model.DefaultIOCEvents[name]

	return model.NormalizedEvent{
		Index:          index,
		Timestamp:      ts,
		EventName:      name,
		ProcessKey:     processKey,
		ParentKey:      parentKey,
		PID:            pid,
		HostPID:        hostPID,
		ParentPID:      parentPID,
		ProcessName:    processName,
		ExecutablePath: execPath,
		ContainerID:    containerID,
		AncestorKeys:   ancestors,
		Fields:         fields,
		DetectedFrom:   detectedFrom,
		IsIOC:          isIOC,
	}, nil
}

func parseNameFromID(id json.RawMessage) string {
	if len(id) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(id, &s); err == nil {
		return s
	}
	return ""
}

func parseTimestamp(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, nil
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t, nil
		}
		if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC(), nil
		}
	}

	var obj struct {
		Seconds string `json:"seconds"`
		Nanos   int32  `json:"nanos"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Seconds != "" {
		sec, err := strconv.ParseInt(obj.Seconds, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse timestamp seconds: %w", err)
		}
		return time.Unix(sec, int64(obj.Nanos)).UTC(), nil
	}

	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		if n > 1_000_000_000_000 {
			return time.Unix(0, n).UTC(), nil
		}
		return time.Unix(0, n).UTC(), nil
	}

	return time.Time{}, fmt.Errorf("unsupported timestamp format")
}

func mergeFields(data, args []rawEventValue) map[string]any {
	fields := make(map[string]any)
	for _, item := range append(data, args...) {
		if item.Name == "" {
			continue
		}
		fields[item.Name] = decodeEventValue(item)
	}
	return fields
}

func decodeEventValue(v rawEventValue) any {
	if v.Str != "" {
		return v.Str
	}
	if v.Int32 != nil {
		return *v.Int32
	}
	if v.UInt32 != nil {
		return *v.UInt32
	}
	if v.Bool != nil {
		return *v.Bool
	}
	if v.StrArray != nil {
		return v.StrArray.Value
	}
	if v.Int32Array != nil {
		return v.Int32Array.Value
	}
	if len(v.Int64) > 0 {
		if n, ok := parseJSONNumber(v.Int64); ok {
			return n
		}
	}
	if len(v.UInt64) > 0 {
		if n, ok := parseJSONNumber(v.UInt64); ok {
			return n
		}
	}
	if len(v.Value) > 0 {
		var s string
		if err := json.Unmarshal(v.Value, &s); err == nil {
			return s
		}
		var n float64
		if err := json.Unmarshal(v.Value, &n); err == nil {
			return n
		}
		var arr []string
		if err := json.Unmarshal(v.Value, &arr); err == nil {
			return arr
		}
		var arrInt []int32
		if err := json.Unmarshal(v.Value, &arrInt); err == nil {
			return arrInt
		}
		var generic any
		if err := json.Unmarshal(v.Value, &generic); err == nil {
			return generic
		}
	}
	return nil
}

func parseJSONNumber(raw json.RawMessage) (int64, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		n, err := strconv.ParseInt(s, 10, 64)
		return n, err == nil
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		return int64(n), true
	}
	return 0, false
}

func extractProcessContext(
	ev rawEvent,
	fields map[string]any,
	ts time.Time,
) (processKey, parentKey string, pid, hostPID, parentPID uint32, processName, execPath, containerID string, ancestors []string) {
	if ev.Workload != nil && ev.Workload.Process != nil {
		p := ev.Workload.Process
		pid = firstNonZero(p.PID, uint32(ev.ProcessID))
		hostPID = firstNonZero(p.HostPID, uint32(ev.HostProcessID), pid)
		if p.Executable != nil {
			execPath = p.Executable.Path
		}
		if p.Thread != nil {
			processName = p.Thread.Name
		}
		startTime := parseThreadStartTime(p.Thread)
		processKey = makeProcessKey(p.UniqueID, pid, hostPID, startTime, ts)
		for _, anc := range p.Ancestors {
			ancKey := makeProcessKey(anc.UniqueID, anc.PID, anc.HostPID, time.Time{}, time.Time{})
			if ancKey != "" {
				ancestors = append(ancestors, ancKey)
			}
		}
		if len(ancestors) > 0 {
			parentKey = ancestors[0]
		}
	}
	if ev.Workload != nil && ev.Workload.Container != nil {
		containerID = ev.Workload.Container.ID
	}

	if processKey == "" {
		pid = firstNonZero(uint32(ev.ProcessID), pid)
		hostPID = firstNonZero(uint32(ev.HostProcessID), hostPID, pid)
		parentPID = uint32(ev.ParentProcessID)
		processName = ev.ProcessName
		start := time.Unix(0, ev.ThreadStartTime).UTC()
		if ev.ProcessEntityID != 0 {
			processKey = fmt.Sprintf("entity:%d", ev.ProcessEntityID)
		} else {
			processKey = makeProcessKey(0, pid, hostPID, start, ts)
		}
		if ev.ParentEntityID != 0 {
			parentKey = fmt.Sprintf("entity:%d", ev.ParentEntityID)
		} else if parentPID != 0 {
			parentKey = fmt.Sprintf("pid:%d", parentPID)
		}
	}

	if parentPID == 0 {
		parentPID = uint32(IntFromField(fields, "parent_pid"))
	}
	if parentKey == "" && parentPID != 0 {
		parentKey = fmt.Sprintf("pid:%d", parentPID)
	}

	if processName == "" {
		processName = StringFromField(fields, "prev_comm")
	}
	if execPath == "" {
		execPath = StringFromField(fields, "pathname", "cmdpath")
	}

	return processKey, parentKey, pid, hostPID, parentPID, processName, execPath, containerID, ancestors
}

func parseThreadStartTime(thread *rawThread) time.Time {
	if thread == nil || len(thread.StartTime) == 0 {
		return time.Time{}
	}
	ts, err := parseTimestamp(thread.StartTime)
	if err != nil {
		return time.Time{}
	}
	return ts
}

func makeProcessKey(uniqueID, pid, hostPID uint32, startTime, fallback time.Time) string {
	if uniqueID != 0 {
		return fmt.Sprintf("uid:%d", uniqueID)
	}
	if !startTime.IsZero() && pid != 0 {
		return fmt.Sprintf("pid:%d@%d", pid, startTime.UnixNano())
	}
	if pid != 0 {
		return fmt.Sprintf("pid:%d", pid)
	}
	if hostPID != 0 && !fallback.IsZero() {
		return fmt.Sprintf("hostpid:%d@%d", hostPID, fallback.UnixNano())
	}
	if hostPID != 0 {
		return fmt.Sprintf("hostpid:%d", hostPID)
	}
	return ""
}

func firstNonZero(values ...uint32) uint32 {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func parseDetectedFrom(raw *rawDetected) *model.DetectedFromEvent {
	if raw == nil {
		return nil
	}
	return &model.DetectedFromEvent{
		ID:   raw.ID,
		Name: raw.Name,
		Data: mergeFields(raw.Data, nil),
	}
}

func StringFromField(fields map[string]any, names ...string) string {
	for _, name := range names {
		if v, ok := fields[name]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func IntFromField(fields map[string]any, name string) int64 {
	v, ok := fields[name]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case string:
		parsed, err := strconv.ParseInt(n, 10, 64)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func StringSliceFromField(fields map[string]any, name string) []string {
	v, ok := fields[name]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func Int32FromField(fields map[string]any, name string) (int32, bool) {
	v, ok := fields[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int32:
		return n, true
	case int64:
		return int32(n), true
	case float64:
		return int32(n), true
	}
	return 0, false
}

func Uint32FromField(fields map[string]any, name string) (uint32, bool) {
	v, ok := fields[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case uint32:
		return n, true
	case int32:
		return uint32(n), true
	case int64:
		return uint32(n), true
	case float64:
		return uint32(n), true
	}
	return 0, false
}

func Uint64FromField(fields map[string]any, name string) (uint64, bool) {
	v, ok := fields[name]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case uint64:
		return n, true
	case int64:
		return uint64(n), true
	case float64:
		return uint64(n), true
	}
	return 0, false
}

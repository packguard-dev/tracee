package mitm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Record is a parsed MITM proxy log entry.
type Record struct {
	Timestamp     time.Time
	Host          string
	Port          int32
	Scheme        string
	URL           string
	Method        string
	SNI           string
	ResponseBytes int64
}

type rawLogLine struct {
	Timestamp    json.RawMessage `json:"timestamp"`
	Destination  rawDestination  `json:"destination"`
	TLS          rawTLS          `json:"tls"`
	PayloadSizes rawPayloadSizes `json:"payload_sizes"`
}

type rawDestination struct {
	Host   string `json:"host"`
	Port   int32  `json:"port"`
	Scheme string `json:"scheme"`
	URL    string `json:"url"`
	Method string `json:"method"`
}

type rawTLS struct {
	SNI string `json:"sni"`
}

type rawPayloadSizes struct {
	ResponseBytes int64 `json:"response_bytes"`
}

var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05.999999",
	"2006-01-02T15:04:05",
}

// ParseFile reads an MITM proxy JSONL file and returns parsed records.
func ParseFile(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	records, err := parseReader(file)
	if err != nil {
		return nil, fmt.Errorf("parse mitm %q: %w", path, err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("parse mitm %q: no valid records", path)
	}
	return records, nil
}

func parseReader(r io.Reader) ([]Record, error) {
	scanner := bufio.NewScanner(r)
	records := make([]Record, 0)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		record, err := parseLine(line)
		if err != nil {
			continue
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func parseLine(line string) (Record, error) {
	var raw rawLogLine
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Record{}, err
	}

	ts, err := parseTimestamp(raw.Timestamp)
	if err != nil {
		return Record{}, err
	}
	if raw.Destination.URL == "" && raw.Destination.Host == "" {
		return Record{}, fmt.Errorf("missing destination")
	}

	return Record{
		Timestamp:     ts,
		Host:          strings.TrimSpace(raw.Destination.Host),
		Port:          raw.Destination.Port,
		Scheme:        strings.TrimSpace(raw.Destination.Scheme),
		URL:           strings.TrimSpace(raw.Destination.URL),
		Method:        strings.TrimSpace(raw.Destination.Method),
		SNI:           strings.TrimSpace(raw.TLS.SNI),
		ResponseBytes: raw.PayloadSizes.ResponseBytes,
	}, nil
}

func parseTimestamp(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, fmt.Errorf("missing timestamp")
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		asString = strings.TrimSpace(asString)
		if asString == "" {
			return time.Time{}, fmt.Errorf("empty timestamp")
		}
		for _, layout := range timestampLayouts {
			if ts, err := time.Parse(layout, asString); err == nil {
				if !hasTimezoneSuffix(asString) {
					return ts.UTC(), nil
				}
				return ts, nil
			}
		}
		return time.Time{}, fmt.Errorf("unsupported timestamp %q", asString)
	}

	var asNumber float64
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		sec := int64(asNumber)
		nsec := int64((asNumber - float64(sec)) * 1e9)
		return time.Unix(sec, nsec).UTC(), nil
	}

	return time.Time{}, fmt.Errorf("invalid timestamp")
}

func hasTimezoneSuffix(value string) bool {
	if strings.HasSuffix(value, "Z") {
		return true
	}
	if idx := strings.LastIndex(value, "+"); idx > strings.Index(value, "T") {
		return true
	}
	if idx := strings.LastIndex(value, "-"); idx > strings.Index(value, "T") {
		return true
	}
	return false
}

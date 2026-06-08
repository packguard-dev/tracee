package mitm

import (
	"encoding/json"
	"fmt"
	"time"
)

// BuildTestFixture returns minimal MITM proxy JSONL aligned with PCAP test fixture timing.
func BuildTestFixture() ([]byte, error) {
	base := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	lines := []map[string]any{
		{
			"timestamp": base.Format("2006-01-02T15:04:05.999999"),
			"destination": map[string]any{
				"host":   "185.199.108.133",
				"port":   443,
				"scheme": "https",
				"url":    "https://raw.githubusercontent.com/packguard-dev/socket-samples/refs/heads/main/synckit/firefox-updater.txt",
				"method": "GET",
			},
			"tls": map[string]any{
				"sni":         "raw.githubusercontent.com",
				"tls_version": "TLSv1.3",
				"alpn":        "http/1.1",
			},
			"payload_sizes": map[string]any{
				"request_bytes":  0,
				"response_bytes": 13287,
				"total_bytes":    13287,
			},
		},
		{
			"timestamp": base.Add(100 * time.Millisecond).Format("2006-01-02T15:04:05.999999"),
			"destination": map[string]any{
				"host":   "94.130.142.35",
				"port":   443,
				"scheme": "https",
				"url":    "https://api.open-meteo.com/v1/forecast?latitude=40.7128",
				"method": "GET",
			},
			"tls": map[string]any{
				"sni":         "api.open-meteo.com",
				"tls_version": "TLSv1.3",
				"alpn":        "http/1.1",
			},
			"payload_sizes": map[string]any{
				"request_bytes":  0,
				"response_bytes": 281,
				"total_bytes":    281,
			},
		},
	}

	var buf []byte
	for _, line := range lines {
		encoded, err := json.Marshal(line)
		if err != nil {
			return nil, fmt.Errorf("marshal fixture line: %w", err)
		}
		buf = append(buf, encoded...)
		buf = append(buf, '\n')
	}
	return buf, nil
}

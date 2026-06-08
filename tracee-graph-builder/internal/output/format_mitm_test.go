package output

import (
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestFormatMitmRequests(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, 6, 7, 8, 29, 3, 0, time.UTC)
	out := model.Output{
		Meta: model.OutputMeta{GeneratedAt: time.Now().UTC()},
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: ts,
				EventName: "non_whitelisted_domain_connection",
				Mitm: &model.MitmEnrichment{
					Source:    "/tmp/mitm_proxy.jsonl",
					WindowSec: 300,
					MatchMode: model.PcapMatchModeHints,
					Requests: []model.MitmRequest{
						{
							Timestamp:     ts,
							Host:          "185.199.108.133",
							Port:          443,
							Scheme:        "https",
							URL:           "https://raw.githubusercontent.com/packguard-dev/socket-samples/refs/heads/main/synckit/firefox-updater.txt",
							Method:        "GET",
							SNI:           "raw.githubusercontent.com",
							ResponseBytes: 13287,
						},
					},
				},
			},
		},
	}

	text := FormatTableOutput(out)
	if !strings.Contains(text, "External requests (mitm)") {
		t.Fatal("missing mitm subsection title")
	}
	if !strings.Contains(text, "raw.githubusercontent.com") {
		t.Fatal("missing mitm url line")
	}
	if !strings.Contains(text, "response_bytes=13287") {
		t.Fatal("missing response_bytes in mitm line")
	}
	if !strings.Contains(text, "sni=raw.githubusercontent.com") {
		t.Fatal("missing sni in mitm line")
	}
}

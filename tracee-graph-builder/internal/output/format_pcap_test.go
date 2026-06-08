package output

import (
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestFormatPcapIndicators(t *testing.T) {
	t.Parallel()

	out := model.Output{
		Meta: model.OutputMeta{GeneratedAt: time.Now().UTC()},
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: time.Now().UTC(),
				EventName: "non_whitelisted_domain_connection",
				Pcap: &model.PcapEnrichment{
					Source:    "/tmp/test.pcapng",
					WindowSec: 300,
					MatchMode: model.PcapMatchModeHints,
					Indicators: []model.ExternalIndicator{
						{IP: "185.199.108.133", Port: 443, Protocol: "TCP"},
						{
							IP:       "185.199.108.133",
							Port:     53,
							Protocol: "DNS",
							Domain:   "raw.githubusercontent.com",
						},
					},
				},
			},
		},
	}

	text := FormatTableOutput(out)
	if !strings.Contains(text, "External indicators (pcap)") {
		t.Fatal("missing pcap subsection title")
	}
	if !strings.Contains(text, "185.199.108.133:443 TCP") {
		t.Fatal("missing tcp indicator line")
	}
	if !strings.Contains(text, "raw.githubusercontent.com") {
		t.Fatal("missing dns indicator line")
	}
}

package detectors

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
)

func TestCalculateEntropy(t *testing.T) {
	t.Parallel()

	low := calculateEntropy("wwwwww")
	high := calculateEntropy("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv")

	assert.Less(t, low, dnsExfiltrationEntropyCutoff)
	assert.Greater(t, high, dnsExfiltrationEntropyCutoff)
}

func TestParseDomainParts(t *testing.T) {
	t.Parallel()

	subdomain, base := parseDomainParts("a.b.example.com")
	assert.Equal(t, "a.b", subdomain)
	assert.Equal(t, "example.com", base)
}

func TestDNSExfiltration_OnEvent(t *testing.T) {
	t.Parallel()

	d := &DNSExfiltration{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	t.Run("ignore non dns event", func(t *testing.T) {
		out, err := d.OnEvent(context.Background(), &v1beta1.Event{Name: "sched_process_exec"})
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("ignore whitelisted query", func(t *testing.T) {
		out, err := d.OnEvent(context.Background(), dnsEventWithSingleQuery("registry.npmjs.org"))
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("ignore reverse dns", func(t *testing.T) {
		out, err := d.OnEvent(context.Background(), dnsEventWithSingleQuery("1.0.0.127.in-addr.arpa"))
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("detect excessive subdomain length", func(t *testing.T) {
		longSubdomain := strings.Repeat("a", dnsExfiltrationMaxSubdomainLen+1) + ".attacker.com"
		out, err := d.OnEvent(context.Background(), dnsEventWithSingleQuery(longSubdomain))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, "excessive_subdomain_length", eventValueAsString(t, out[0].Data, "heuristic"))
	})

	t.Run("detect high entropy", func(t *testing.T) {
		entropyQuery := "a9z8x7w6v5u4t3s2r1q0p9o8n7m6l5k4.attacker.com"
		out, err := d.OnEvent(context.Background(), dnsEventWithSingleQuery(entropyQuery))
		require.NoError(t, err)
		require.Len(t, out, 1)

		assert.Equal(t, "high_entropy_payload", eventValueAsString(t, out[0].Data, "heuristic"))
	})

	t.Run("detect high frequency burst", func(t *testing.T) {
		var out []detection.DetectorOutput
		var err error
		for i := 0; i < dnsExfiltrationFrequencyCutoff+10; i++ {
			query := "host.attacker-frequency.com"
			out, err = d.OnEvent(context.Background(), dnsEventWithSingleQuery(query))
			require.NoError(t, err)
			if len(out) > 0 {
				break
			}
		}

		require.Len(t, out, 1)
		assert.Equal(t, "high_frequency_burst", eventValueAsString(t, out[0].Data, "heuristic"))
	})
}

func dnsEventWithSingleQuery(query string) *v1beta1.Event {
	return &v1beta1.Event{
		Name: "net_packet_dns_request",
		Data: []*v1beta1.EventValue{
			{
				Name: "dns_questions",
				Value: &v1beta1.EventValue_DnsQuestions{
					DnsQuestions: &v1beta1.DnsQuestions{
						Questions: []*v1beta1.DnsQueryData{
							{Query: query},
						},
					},
				},
			},
		},
	}
}

func eventValueAsString(t *testing.T, data []*v1beta1.EventValue, name string) string {
	t.Helper()
	for _, item := range data {
		if item.GetName() == name {
			return item.GetStr()
		}
	}
	t.Fatalf("missing event data value %q", name)
	return ""
}

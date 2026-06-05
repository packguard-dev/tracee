package detectors

import (
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	dnsExfiltrationMaxSubdomainLen = 60
	dnsExfiltrationEntropyCutoff   = 4.5
	dnsExfiltrationFrequencyCutoff = 150
	dnsExfiltrationWindowTTL       = 5 * time.Minute
	dnsExfiltrationMaxDomains      = 4096
)

func init() {
	register(&DNSExfiltration{})
}

// DNSExfiltration detects DNS tunneling and DNS-based data exfiltration patterns.
type DNSExfiltration struct {
	logger      detection.Logger
	cacheMu     sync.Mutex
	queryCounts *expirable.LRU[string, *atomic.Int64]
	whitelist   []string
}

func (d *DNSExfiltration) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-005",
		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_dns_request",
					Dependency: detection.DependencyRequired,
				},
			},
		},
		ProducedEvent: v1beta1.EventDefinition{
			Name:        "dns_exfiltration",
			Description: "Potential DNS tunneling or DNS data exfiltration detected",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "query", Type: "const char*"},
				{Name: "base_domain", Type: "const char*"},
				{Name: "subdomain", Type: "const char*"},
				{Name: "heuristic", Type: "const char*"},
				{Name: "metric", Type: "int"},
			},
		},
		ThreatMetadata: &v1beta1.Threat{
			Name:        "DNS Exfiltration / Tunneling",
			Description: "Suspicious DNS query structure indicates potential command and control or data exfiltration over DNS",
			Severity:    v1beta1.Severity_HIGH,
			Mitre: &v1beta1.Mitre{
				Tactic: &v1beta1.MitreTactic{
					Name: "Exfiltration",
				},
				Technique: &v1beta1.MitreTechnique{
					Id:   "T1048/T1071.004",
					Name: "Exfiltration Over Alternative Protocol (DNS)",
				},
			},
		},
		AutoPopulate: detection.AutoPopulateFields{
			Threat:          true,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *DNSExfiltration) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.queryCounts = expirable.NewLRU[string, *atomic.Int64](
		dnsExfiltrationMaxDomains,
		nil,
		dnsExfiltrationWindowTTL,
	)

	for _, domain := range defaultWhitelist {
		d.whitelist = append(d.whitelist, normalizeDomain(domain))
	}

	d.logger.Infow(
		"DNSExfiltration detector initialized",
		"whitelist_size", len(d.whitelist),
		"window_ttl", dnsExfiltrationWindowTTL.String(),
		"max_domains", dnsExfiltrationMaxDomains,
	)
	return nil
}

func (d *DNSExfiltration) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	_ = ctx

	if event.GetName() != "net_packet_dns_request" {
		return nil, nil
	}

	queries := extractDNSQueries(event)
	if len(queries) == 0 {
		return nil, nil
	}

	for _, query := range queries {
		normalizedQuery := normalizeDomain(query.Query)
		subdomain, baseDomain := parseDomainParts(normalizedQuery)
		if shouldRejectDNSQuery(baseDomain, normalizedQuery, d.whitelist) {
			continue
		}

		subdomainLength := len(subdomain)
		if subdomainLength > dnsExfiltrationMaxSubdomainLen {
			return d.detected(
				normalizedQuery,
				baseDomain,
				subdomain,
				"excessive_subdomain_length",
				int32(subdomainLength),
			), nil
		}

		entropy := calculateEntropy(subdomain)
		if entropy > dnsExfiltrationEntropyCutoff {
			return d.detected(
				normalizedQuery,
				baseDomain,
				subdomain,
				"high_entropy_payload",
				int32(math.Round(entropy*100)),
			), nil
		}

		count := d.incrementDomainCount(baseDomain)
		if count > dnsExfiltrationFrequencyCutoff {
			return d.detected(
				normalizedQuery,
				baseDomain,
				subdomain,
				"high_frequency_burst",
				int32(count),
			), nil
		}
	}

	return nil, nil
}

func (d *DNSExfiltration) detected(
	query string,
	baseDomain string,
	subdomain string,
	heuristic string,
	metric int32,
) []detection.DetectorOutput {
	d.logger.Infow(
		"DNS exfiltration heuristic matched",
		"query", query,
		"base_domain", baseDomain,
		"subdomain", subdomain,
		"heuristic", heuristic,
		"metric", metric,
	)

	return detection.DetectedWithData(
		[]*v1beta1.EventValue{
			v1beta1.NewStringValue("query", query),
			v1beta1.NewStringValue("base_domain", baseDomain),
			v1beta1.NewStringValue("subdomain", subdomain),
			v1beta1.NewStringValue("heuristic", heuristic),
			v1beta1.NewInt32Value("metric", metric),
		},
	)
}

func (d *DNSExfiltration) incrementDomainCount(baseDomain string) int64 {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	counter, ok := d.queryCounts.Get(baseDomain)
	if !ok {
		counter = &atomic.Int64{}
		d.queryCounts.Add(baseDomain, counter)
	}

	return counter.Add(1)
}

func (d *DNSExfiltration) isWhitelisted(domain string) bool {
	for _, allowed := range d.whitelist {
		if isAllowedDomain(domain, allowed) {
			return true
		}
	}
	return false
}

func extractDNSQueries(event *v1beta1.Event) []*v1beta1.DnsQueryData {
	for _, data := range event.GetData() {
		if data.GetName() != "dns_questions" {
			continue
		}
		if questions := data.GetDnsQuestions(); questions != nil {
			return questions.GetQuestions()
		}
		break
	}
	return nil
}

func shouldRejectDNSQuery(baseDomain, fullDomain string, whitelist []string) bool {
	if baseDomain == "" || fullDomain == "" {
		return true
	}

	if strings.HasSuffix(fullDomain, ".in-addr.arpa") || strings.HasSuffix(fullDomain, ".ip6.arpa") {
		return true
	}

	for _, allowed := range whitelist {
		if isAllowedDomain(fullDomain, allowed) {
			return true
		}
	}

	return false
}

func parseDomainParts(domain string) (subdomain string, baseDomain string) {
	if domain == "" {
		return "", ""
	}

	parts := strings.Split(domain, ".")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			filtered = append(filtered, part)
		}
	}

	if len(filtered) < 2 {
		return "", ""
	}

	baseDomain = filtered[len(filtered)-2] + "." + filtered[len(filtered)-1]
	if len(filtered) == 2 {
		return "", baseDomain
	}

	return strings.Join(filtered[:len(filtered)-2], "."), baseDomain
}

func calculateEntropy(value string) float64 {
	if value == "" {
		return 0
	}

	freq := make(map[rune]float64)
	for _, char := range value {
		freq[char]++
	}

	total := float64(len([]rune(value)))
	entropy := 0.0
	for _, count := range freq {
		probability := count / total
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

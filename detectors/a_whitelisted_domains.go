package detectors

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
)

var defaultWhitelist = []string{
	"registry.npmjs.org",
	"pypi.org",
	"files.pythonhosted.org",
	"nodejs.org",
	"node.js.org",
	"marketplace.visualstudio.com",
	"main.vscode-cdn.net",
	"storage.googleapis.com",
}

var suffixWhitelist = []string{
	".us-central1-a.c.k8s-packamal.internal",
	".c.k8s-packamal.internal",
	".packamal-dev.svc.cluster.local",
	".svc.cluster.local",
	".cluster.local",
	".google.internal",
}

var sortSuffixWhitelistOnce sync.Once

func init() {
	register(&NonWhitelistedDomainConnection{})
}

type NonWhitelistedDomainConnection struct {
	logger    detection.Logger
	whitelist []string
}

func (d *NonWhitelistedDomainConnection) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-002",

		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "net_packet_dns_request",
					Dependency: detection.DependencyRequired,
				},
			},
		},

		ProducedEvent: v1beta1.EventDefinition{
			Name:        "non_whitelisted_domain_connection",
			Description: "Attempted to connect to a non-whitelisted domain",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "domain", Type: "const char*"},
			},
		},

		AutoPopulate: detection.AutoPopulateFields{
			Threat:          false,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func normalizeDomain(domain string) string {
	sortSuffixWhitelistOnce.Do(func() {
		sort.Slice(suffixWhitelist, func(i, j int) bool {
			return len(suffixWhitelist[i]) > len(suffixWhitelist[j])
		})
	})

	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	for _, suffix := range suffixWhitelist {
		if strings.HasSuffix(domain, suffix) {
			domain = strings.TrimSuffix(domain, suffix)
			break
		}
	}
	return strings.TrimSuffix(domain, ".")
}

func isAllowedDomain(domain, allowed string) bool {
	return domain == allowed || strings.HasSuffix(domain, "."+allowed)
}

func (d *NonWhitelistedDomainConnection) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	for _, domain := range defaultWhitelist {
		d.whitelist = append(d.whitelist, normalizeDomain(domain))
	}
	d.logger.Infow(
		"NonWhitelistedDomainConnection detector initialized",
		"whitelist_size", len(d.whitelist),
	)
	return nil
}

func (d *NonWhitelistedDomainConnection) isWhitelisted(domain string) bool {
	domain = normalizeDomain(domain)
	for _, allowed := range d.whitelist {
		if isAllowedDomain(domain, allowed) {
			return true
		}
	}
	return false
}

func (d *NonWhitelistedDomainConnection) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	_ = ctx

	if event.Name != "net_packet_dns_request" {
		return nil, nil
	}

	var dnsQueries []*v1beta1.DnsQueryData
	found := false

	for _, data := range event.GetData() {
		if data.GetName() != "dns_questions" {
			continue
		}
		if questions := data.GetDnsQuestions(); questions != nil {
			dnsQueries = questions.GetQuestions()
			found = true
		}
		break
	}

	if !found {
		return nil, nil
	}

	for _, query := range dnsQueries {
		domain := normalizeDomain(query.Query)
		if !d.isWhitelisted(domain) {
			if pid, ok := pidFromEventWorkload(event); ok {
				markSuspicionAfterNonWhitelistedDNS(pid, domain)
			}

			return detection.DetectedWithData(
				[]*v1beta1.EventValue{
					v1beta1.NewStringValue("domain", domain),
				},
			), nil
		}
	}

	return nil, nil
}

func pidFromEventWorkload(event *v1beta1.Event) (uint32, bool) {
	w := event.GetWorkload()
	if w == nil {
		return 0, false
	}
	p := w.GetProcess()
	if p == nil {
		return 0, false
	}
	pid := p.GetPid()
	if pid == nil {
		return 0, false
	}
	return pid.Value, true
}

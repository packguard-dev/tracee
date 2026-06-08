package netutil

import (
	"sort"
	"strings"
	"sync"
)

var (
	suffixWhitelist = []string{
		".us-central1-a.c.k8s-packamal.internal",
		".c.k8s-packamal.internal",
		".packamal-dev.svc.cluster.local",
		".svc.cluster.local",
		".cluster.local",
		".google.internal",
	}

	sortSuffixWhitelistOnce sync.Once
)

// NormalizeDomain strips internal cluster suffixes and lowercases a DNS name.
func NormalizeDomain(domain string) string {
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

// DomainMatches reports whether candidate equals or is a subdomain of hint.
func DomainMatches(candidate, hint string) bool {
	candidate = NormalizeDomain(candidate)
	hint = NormalizeDomain(hint)
	if candidate == "" || hint == "" {
		return false
	}
	return candidate == hint || strings.HasSuffix(candidate, "."+hint)
}

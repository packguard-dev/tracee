package netutil

import "testing"

func TestNormalizeDomainStripsClusterSuffix(t *testing.T) {
	t.Parallel()

	got := NormalizeDomain("app.packamal-dev.svc.cluster.local.")
	want := "app"
	if got != want {
		t.Fatalf("NormalizeDomain() = %q, want %q", got, want)
	}
}

func TestDomainMatches(t *testing.T) {
	t.Parallel()

	if !DomainMatches("foo.registry.npmjs.org", "registry.npmjs.org") {
		t.Fatal("expected subdomain match")
	}
	if DomainMatches("evil.example.com", "registry.npmjs.org") {
		t.Fatal("unexpected domain match")
	}
}

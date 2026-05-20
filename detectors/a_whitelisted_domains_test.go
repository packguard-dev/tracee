package detectors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/detectors/testutil"
	"google.golang.org/protobuf/types/known/wrapperspb"
)
func TestNonWhitelistedDomainConnection_isWhitelisted(t *testing.T) {
	t.Parallel()

	d := &NonWhitelistedDomainConnection{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	allowed := []string{
		"registry.npmjs.org",
		"registry.npmjs.org.",
		"foo.registry.npmjs.org",
		"foo.bar.registry.npmjs.org",
		"registry.npmjs.org.google.internal",
		"registry.npmjs.org.cluster.local",
		"registry.npmjs.org.svc.cluster.local",
		"registry.npmjs.org.us-central1-a.c.k8s-packamal.internal",
		"foo.registry.npmjs.org.google.internal",
		"foo.registry.npmjs.org.cluster.local",
		"pypi.org",
		"files.pythonhosted.org",
		"cdn.files.pythonhosted.org",
		"nodejs.org",
		"download.nodejs.org",
		"marketplace.visualstudio.com",
		"foo.marketplace.visualstudio.com",
		"main.vscode-cdn.net",
		"storage.googleapis.com",
		"storage.googleapis.com.google.internal",
		"foo.storage.googleapis.com",
		"foo.storage.googleapis.com.google.internal",
		"foo.storage.googleapis.com.cluster.local",
	}

	for _, domain := range allowed {
		t.Run("allowed_"+domain, func(t *testing.T) {
			t.Parallel()
			assert.True(t, d.isWhitelisted(domain), "expected allow: %q", domain)
		})
	}

	blocked := []string{
		"evil.com",
		"google.com",
		"npmjs.org",
		"evilnpmjs.org",
		"registry.npmjs.org.evil.com",
		"registry.npmjs.orgevil.com",
		"evil.pypi.co",
		"pypi.org.evil.com",
		"storage-googleapis.com",
		"storage.googleapis.com.evil.com",
		"main.vscode-cdn.net.evil.com",
		"evilmain.vscode-cdn.net",
		"cluster.local",
		"google.internal",
		"foo.evil.cluster.local",
		"foo.evil.google.internal",
		"foo.registry.npmjs.org.evil.com",
		"foo.registry.npmjs.org.evil.com.google.internal",
	}

	for _, domain := range blocked {
		t.Run("blocked_"+domain, func(t *testing.T) {
			t.Parallel()
			assert.False(t, d.isWhitelisted(domain), "expected block: %q", domain)
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"Registry.NPMJS.ORG.", "registry.npmjs.org"},
		{"host.svc.cluster.local", "host"},
		{"host.google.internal", "host"},
		{"registry.npmjs.org.us-central1-a.c.k8s-packamal.internal", "registry.npmjs.org"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, normalizeDomain(tc.in))
		})
	}
}

func TestIsAllowedDomain(t *testing.T) {
	t.Parallel()

	assert.True(t, isAllowedDomain("registry.npmjs.org", "registry.npmjs.org"))
	assert.True(t, isAllowedDomain("foo.registry.npmjs.org", "registry.npmjs.org"))
	assert.False(t, isAllowedDomain("registry.npmjs.org.evil.com", "registry.npmjs.org"))
	assert.False(t, isAllowedDomain("evilmain.vscode-cdn.net", "main.vscode-cdn.net"))
}

func TestNonWhitelistedDomainConnection_OnEvent(t *testing.T) {
	t.Parallel()

	d := &NonWhitelistedDomainConnection{}
	err := d.Init(detection.DetectorParams{Logger: &testutil.MockLogger{}})
	require.NoError(t, err)

	dnsEvent := func(query string) *v1beta1.Event {
		return &v1beta1.Event{
			Name: "net_packet_dns_request",
			Workload: &v1beta1.Workload{
				Process: &v1beta1.Process{
					Pid: wrapperspb.UInt32(1001),
				},
			},
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

	out, err := d.OnEvent(context.Background(), dnsEvent("registry.npmjs.org"))
	require.NoError(t, err)
	assert.Empty(t, out, "whitelisted DNS query should not detect")

	out, err = d.OnEvent(context.Background(), dnsEvent("evil.com"))
	require.NoError(t, err)
	require.Len(t, out, 1, "non-whitelisted DNS query should detect")
	require.Len(t, out[0].Data, 1)
	assert.Equal(t, "domain", out[0].Data[0].GetName())
	assert.Equal(t, "evil.com", out[0].Data[0].GetStr())

	out, err = d.OnEvent(context.Background(), &v1beta1.Event{Name: "sched_process_exec"})
	require.NoError(t, err)
	assert.Empty(t, out, "non-DNS event should be ignored")
}

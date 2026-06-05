package detectors

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/detection"
	"github.com/aquasecurity/tracee/common/parsers"
)


var decoyExactPaths = map[string]struct{}{
	"/root/.npmrc":                             {},
	"/root/.yarnrc.yml":                        {},
	"/root/.netrc":                             {},
	"/root/.gitconfig":                         {},
	"/root/.env":                               {},
	"/root/.bash_history":                      {},
	"/root/.zsh_history":                       {},
	"/root/.mysql_history":                     {},
	"/root/.psql_history":                      {},
	"/root/.config/linode-cli":                 {},
	"/root/.config/hub":                        {},
	"/root/.terraform.d/credentials.tfrc.json": {},
}

// prefixEntry pairs a pathname prefix with a coarse category label for alerting.
type prefixEntry struct {
	prefix string
	cat    string
}

var decoyPrefixesSorted []prefixEntry

func init() {
	register(&DecoyFileRead{})
	decoyPrefixesSorted = decoyPrefixesForSorting()
	sort.Slice(decoyPrefixesSorted, func(i, j int) bool {
		return len(decoyPrefixesSorted[i].prefix) > len(decoyPrefixesSorted[j].prefix)
	})
}

func decoyPrefixesForSorting() []prefixEntry {
	return []prefixEntry{
		{`/root/.config/Microsoft/Microsoft Teams/`, "teams"},
		{`/root/.local/share/com.vercel.cli/`, "cloud_cli"},
		{`/root/.railway/`, "cloud_cli"},
		{`/root/.snowsql/`, "cloud_cli"},
		{`/root/.doppler/`, "secrets_manager"},
		{`/root/.docker/`, "container"},
		{`/root/.aws/`, "cloud_creds"},
		{`/root/.azure/`, "cloud_creds"},
		{`/root/.config/gcloud/`, "cloud_creds"},
		{`/root/.oci/`, "cloud_creds"},
		{`/root/.config/doctl/`, "cloud_creds"},
		{`/root/.config/scw/`, "cloud_creds"},
		{`/root/.config/hcloud/`, "cloud_creds"},
		{`/root/.fly/`, "cloud_creds"},
		{`/root/.vercel/`, "cloud_creds"},
		{`/root/.aliyun/`, "cloud_creds"},
		{`/root/.bluemix/`, "cloud_creds"},
		{`/root/.mc/`, "cloud_creds"},
		{`/root/.sfdx/`, "cloud_creds"},
		{`/root/.ssh/`, "ssh"},
		{`/root/.kube/`, "kube"},
		{`/var/run/secrets/kubernetes.io/serviceaccount/`, "kube"},
		{`/root/.config/helm/`, "container"},
		{`/root/.rancher/`, "container"},
		{`/root/.config/gh/`, "vcs"},
		{`/root/.config/glab-cli/`, "vcs"},
		{`/root/projects/infra/`, "iac"},
		{`/root/app/`, "app_secrets"},
		{`/root/.local/share/keyrings/`, "keyring"},
		{`/root/.local/share/kwalletd/`, "keyring"},
		{`/root/.config/filezilla/`, "remote_desktop"},
		{`/root/.local/share/remmina/`, "remote_desktop"},
		{`/root/vpn/`, "vpn"},
		{`/root/Library/`, "local_secrets_store"},
	}
}

func isDecoyPath(path string) bool {
	if path == "" {
		return false
	}
	path = filepath.Clean(path)

	if _, ok := decoyExactPaths[path]; ok {
		return true
	}

	for _, pe := range decoyPrefixesSorted {
		dir := strings.TrimSuffix(pe.prefix, "/")
		if path == dir || strings.HasPrefix(path, pe.prefix) {
			return true
		}
	}

	return false
}

func decoyCategory(path string) string {
	path = filepath.Clean(path)

	if _, ok := decoyExactPaths[path]; ok {
		switch {
		case strings.HasSuffix(path, "history"):
			return "shell_history"
		case path == "/root/.env":
			return "env_file"
		case strings.Contains(path, "terraform"):
			return "iac"
		default:
			return "cloud_or_vcs"
		}
	}

	for _, pe := range decoyPrefixesSorted {
		dir := strings.TrimSuffix(pe.prefix, "/")
		if path == dir || strings.HasPrefix(path, pe.prefix) {
			return pe.cat
		}
	}

	return "unknown"
}

// DecoyFileRead detects reads of honeypot credential paths from the sandbox image.
type DecoyFileRead struct {
	logger detection.Logger
}

func (d *DecoyFileRead) GetDefinition() detection.DetectorDefinition {
	return detection.DetectorDefinition{
		ID: "TRC-004",

		Requirements: detection.DetectorRequirements{
			Events: []detection.EventRequirement{
				{
					Name:       "security_file_open",
					Dependency: detection.DependencyRequired,
				},
			},
		},

		ProducedEvent: v1beta1.EventDefinition{
			Name:        "decoy_file_read",
			Description: "Process opened a honeypot credential decoy file for reading",
			Version: &v1beta1.Version{
				Major: 1,
				Minor: 0,
				Patch: 0,
			},
			Fields: []*v1beta1.EventField{
				{Name: "file_path", Type: "const char*"},
				{Name: "decoy_category", Type: "const char*"},
			},
		},

		AutoPopulate: detection.AutoPopulateFields{
			Threat:          false,
			DetectedFrom:    true,
			ProcessAncestry: true,
		},
	}
}

func (d *DecoyFileRead) Init(params detection.DetectorParams) error {
	d.logger = params.Logger
	d.logger.Infow("DecoyFileRead detector initialized")
	return nil
}

func (d *DecoyFileRead) OnEvent(
	ctx context.Context,
	event *v1beta1.Event,
) ([]detection.DetectorOutput, error) {
	_ = ctx

	if event.GetName() != "security_file_open" {
		return nil, nil
	}

	pathname, err := v1beta1.GetDataSafe[string](event, "pathname")
	if err != nil || pathname == "" {
		pathname = extractStringField(event, "pathname")
	}
	if pathname == "" || !isDecoyPath(pathname) {
		return nil, nil
	}

	flags, err := v1beta1.GetDataSafe[int32](event, "flags")
	if err != nil {
		return nil, nil
	}
	if !parsers.IsFileRead(int(flags)) {
		return nil, nil
	}

	d.logger.Infow("decoy credential file opened for read", "path", pathname)

	return detection.DetectedWithData(
		[]*v1beta1.EventValue{
			v1beta1.NewStringValue("file_path", pathname),
			v1beta1.NewStringValue("decoy_category", decoyCategory(pathname)),
		},
	), nil
}

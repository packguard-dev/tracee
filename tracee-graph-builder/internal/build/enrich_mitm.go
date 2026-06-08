package build

import (
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/mitm"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

// EnrichFromMitm attaches MITM proxy requests from a JSONL file to IOCs.
func EnrichFromMitm(out model.Output, mitmPath string, window time.Duration) (model.Output, error) {
	if mitmPath == "" {
		return out, nil
	}
	if out.Meta.MitmSource == "" {
		out.Meta.MitmSource = mitmPath
	}

	idx, err := mitm.OpenIndex(mitmPath)
	if err != nil {
		return out, err
	}

	return mitm.EnrichIOCs(out, idx, mitm.EnrichOptions{
		Source: mitmPath,
		Window: window,
	}), nil
}

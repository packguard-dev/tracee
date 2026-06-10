package build

import (
	"time"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/correlate"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/filter"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/graph"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/parallel"
)

func FromEvents(events []model.NormalizedEvent, opts model.BuildOptions) model.Output {
	workers := parallel.WorkerCount(opts.Workers)

	events = filter.DedupFileEvents(events, 5*time.Minute)
	events = filter.DedupNetworkEvents(events, 30*time.Second)

	builder := graph.NewBuilder()
	builder.IngestParallel(events, workers)

	correlator := correlate.New(opts.CorrelationWindow)
	correlator.ApplyParallel(builder, workers)

	return model.Output{
		Meta: model.OutputMeta{
			GeneratedAt:          time.Now().UTC(),
			InputEvents:          len(events),
			CorrelationWindowSec: int(opts.CorrelationWindow.Seconds()),
		},
		ProcessTree: model.ProcessTree{
			Nodes: builder.Nodes(),
			Roots: builder.Roots(),
		},
		Files:        builder.Files(),
		Networks:     builder.Networks(),
		IOCs:         builder.IOCs(),
		PathFileIdentity: builder.PathFileIdentityIndex(),
	}
}

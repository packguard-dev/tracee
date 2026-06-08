package build

import (
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/artifacts"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/payload"
)

// EnrichPayloads resolves payload path, dev/inode, and optional artifact sha256 for each IOC.
func EnrichPayloads(out model.Output, artifactsPath string) (model.Output, error) {
	store, err := artifacts.OpenOptional(artifactsPath)
	if err != nil {
		return out, err
	}
	if store != nil {
		defer store.Close()
	}

	nodes := out.ProcessTree.Nodes
	pathIndex := out.PathDevInode
	enriched := make([]model.IOCRecord, len(out.IOCs))

	for i, ioc := range out.IOCs {
		enriched[i] = enrichOneIOC(ioc, nodes, pathIndex, store, artifactsPath != "")
	}

	out.IOCs = enriched
	out.PathDevInode = nil
	return out, nil
}

func enrichOneIOC(
	ioc model.IOCRecord,
	nodes map[string]model.ProcessNode,
	pathIndex map[string][]model.DevInodeRef,
	store *artifacts.Store,
	artifactsRequested bool,
) model.IOCRecord {
	ioc = payload.EnrichIOC(ioc, nodes, pathIndex)
	if ioc.Payload == nil {
		return ioc
	}

	if ioc.Payload.Status == model.PayloadStatusNotInEvents ||
		ioc.Payload.Status == model.PayloadStatusNoPath {
		return ioc
	}

	if !artifactsRequested {
		ioc.Payload.Status = ""
		return ioc
	}

	node := nodes[ioc.ProcessKey]
	candidates := payload.ResolveDevInode(pathIndex, ioc.Payload.Path)
	data, entryPath, err := store.FindWriteArtifact(node.ContainerID, candidates)
	if err != nil {
		ioc.Payload.Status = model.PayloadStatusNotInZip
		return ioc
	}

	ioc.Payload.SHA256 = artifacts.SHA256Hex(data)
	ioc.Payload.ArtifactPath = entryPath
	ioc.Payload.Status = model.PayloadStatusFound
	payload.ApplyClassification(ioc.Payload, ioc.Payload.Path, data)
	return ioc
}

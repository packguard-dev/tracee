package output

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/tracee/tracee-graph-builder/internal/model"
)

func TestFormatTableOutputPayload(t *testing.T) {
	t.Parallel()

	out := model.Output{
		Meta: model.OutputMeta{
			GeneratedAt:          time.Now().UTC(),
			InputEvents:          1,
			CorrelationWindowSec: 300,
		},
		IOCs: []model.IOCRecord{
			{
				ID:        "ioc-1",
				Timestamp: time.Now().UTC(),
				EventName: "decoy_file_read",
				ProcessKey: "uid:17",
				Payload: &model.PayloadInfo{
					Path:   "/app/AppUpdates/updater.py",
					Dev:    265289729,
					Inode:  354727,
					SHA256: "abc123",
					Status: model.PayloadStatusFound,
				},
			},
		},
	}

	text := FormatTableOutput(out)
	assert.Contains(t, text, "Payload:       /app/AppUpdates/updater.py")
	assert.Contains(t, text, "Payload dev:   265289729")
	assert.Contains(t, text, "Payload inode: 354727")
	assert.Contains(t, text, "Payload sha256: abc123")
}

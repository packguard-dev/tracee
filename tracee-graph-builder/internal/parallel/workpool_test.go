package parallel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunProcessesAllJobs(t *testing.T) {
	t.Parallel()

	var count atomic.Int32
	err := Run(context.Background(), 4, 20, func(index int) error {
		count.Add(1)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, int32(20), count.Load())
}

func TestRunPropagatesFirstError(t *testing.T) {
	t.Parallel()

	err := Run(context.Background(), 4, 10, func(index int) error {
		if index == 3 {
			return errors.New("job failed")
		}
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "job failed")
}

func TestWorkerCount(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 8, WorkerCount(8))
	assert.Equal(t, WorkerCount(0), WorkerCount(0))
}

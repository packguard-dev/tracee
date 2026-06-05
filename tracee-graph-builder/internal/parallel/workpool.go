package parallel

import (
	"context"
	"runtime"
	"sync"
)

// WorkerCount returns requested when positive, otherwise GOMAXPROCS.
func WorkerCount(requested int) int {
	if requested > 0 {
		return requested
	}
	return runtime.GOMAXPROCS(0)
}

// JobFunc processes a single job identified by index.
type JobFunc func(index int) error

// Run executes n jobs with a worker pool. The first error cancels remaining work.
func Run(ctx context.Context, workers, n int, fn JobFunc) error {
	if n == 0 {
		return nil
	}
	if workers <= 0 {
		workers = WorkerCount(0)
	}
	if workers > n {
		workers = n
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan int, workers*2)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := fn(i); err != nil {
					once.Do(func() {
						firstErr = err
						cancel()
					})
					return
				}
			}
		}()
	}

	for i := range n {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	return nil
}

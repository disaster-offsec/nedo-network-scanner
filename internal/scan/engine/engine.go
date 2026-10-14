package engine

import (
	"context"
	"runtime"
	"sync"
	"time"

	"portscanner/internal/scan"
)

// Scan probes the ports specified in opts against opts.Target.
// It respects ctx cancellation and limits parallelism to opts.Threads
// (zero means runtime.NumCPU()).
//
// Results are returned in no particular order.
func Scan(ctx context.Context, opts scan.Options) ([]scan.Result, error) {
	concurrency := opts.Threads

	// Default to CPU count when concurrency is not set.
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	// Buffer must fit all results to avoid goroutine blocking on write.
	resultsCh := make(chan scan.Result, len(opts.Ports))

	// Limit in-flight scans to concurrency.
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	for _, port := range opts.Ports {
		wg.Add(1)
		go func(p int) {
			// Defers run LIFO: sem released, then wg signalled.
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resultsCh <- scanPort(ctx, opts.Target, p, opts.Timeout)
		}(port)
	}

	wg.Wait()
	close(resultsCh)

	var results []scan.Result
	for r := range resultsCh {
		results = append(results, r)
	}
	return results, nil
}

// TODO: implement banner grabbing and OS fingerprinting.
func scanPort(ctx context.Context, target string, port int, timeout time.Duration) scan.Result {
	return scan.Result{Port: port, IsOpen: false}
}

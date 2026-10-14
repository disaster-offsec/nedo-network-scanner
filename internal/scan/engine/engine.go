package engine

import (
	"context"
	"net"
	"runtime"
	"strconv"
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

// scanPort probes a single TCP port. It returns IsOpen=true if the
// connection succeeds. Banner grabbing and OS fingerprinting are TODO.
func scanPort(parentCtx context.Context, target string, port int, timeout time.Duration) scan.Result {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	
	address := net.JoinHostPort(target, strconv.Itoa(port))
	
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return scan.Result{Port: port, IsOpen: false}
	}
	
	defer conn.Close()

	return scan.Result{Port: port, IsOpen: true}
}

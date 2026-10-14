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
// connection succeeds, and attempts to read a banner. If the server
// sends nothing on connect, it sends a HEAD request as a fallback.
// OS fingerprinting is TODO.
func scanPort(parentCtx context.Context, target string, port int, timeout time.Duration) scan.Result {
	result := scan.Result{Port: port, IsOpen: false}
	
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()
	
	address := net.JoinHostPort(target, strconv.Itoa(port))
	
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	
	if err != nil {
		return result
	}

	defer conn.Close()
	
	result.IsOpen = true

	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buffer := make([]byte, 2048)

	// Errors are expected: timeout means no banner, EOF means server closed.
	n, _ := conn.Read(buffer)
	
	if n == 0 {
		// banner is unknown, so try HEAD request
		conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		// TODO: probes := map[int]string
		// depends on port, different banner grabbing approaches

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ = conn.Read(buffer)
	}

	if n > 0 {
		result.Banner = string(buffer[:n])
	}

	return result
}

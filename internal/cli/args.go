package cli

import (
	"flag"
	"time"

	"portscanner/internal/scan"
)

// Parse reads CLI arguments and returns a Config.
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("portscanner", flag.ContinueOnError)

	var target, ports, output, format string
	var timeout, threads int

	fs.StringVar(&target, "t", "127.0.0.1", "target host")
	fs.StringVar(&target, "target", "127.0.0.1", "target host")

	fs.StringVar(&ports, "p", "22,80,443,8000", "ports")
	fs.StringVar(&ports, "ports", "22,80,443,8000", "ports")

	fs.IntVar(&timeout, "timeout", 2, "timeout in seconds")
	fs.IntVar(&threads, "threads", 0, "concurrency")

	fs.StringVar(&output, "o", "", "output file")
	fs.StringVar(&output, "output", "", "output file")

	fs.StringVar(&format, "f", "text", "output format")
	fs.StringVar(&format, "format", "text", "output format")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &Config{
		Scan: scan.Options{
			Target:  target,
			Timeout: time.Duration(timeout) * time.Second,
			Threads: threads,
		},
		Output: output,
		Format: Format(format),
	}, nil
}

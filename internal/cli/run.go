package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"portscanner/internal/export"
	"portscanner/internal/scan"
	"portscanner/internal/scan/engine"
)

func Run(args []string, stdout, stderr io.Writer) int {
	cfg, err := Parse(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	ctx := context.Background()
	results, err := engine.Scan(ctx, cfg.Scan)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	
	// Filter to open ports only — the report should not include closed ones.
	var open []scan.Result
	for _, r := range results {
		if r.IsOpen {
			open = append(open, r)
		}
	}

	report := export.Report{
		Target:     cfg.Scan.Target,
		TotalPorts: len(cfg.Scan.Ports),
		Timestamp:  time.Now(),
		Results:    open,
	}

	var data []byte
	switch cfg.Format {
	case "json":
		data, err = export.ToJSON(report)
	case "csv":
		data, err = export.ToCSV(report)
	case "text":
		data, err = export.ToTXT(report)
	default:
		fmt.Fprintf(stderr, "unknown format: %s\n", cfg.Format)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	if cfg.Output == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	} else {
		if err := os.WriteFile(cfg.Output, data, 0644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	return 0
}

package cli

import (
	"portscanner/internal/scan"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

type Config struct {
	Scan   scan.Options
	Output string
	Format Format
}

package export

import (
	"time"

	"portscanner/internal/scan"
)

// Report holds data for a single scan run
type Report struct {
	Target		string
	TotalPorts	int
	Timestamp	time.Time
	Results		[]scan.Result
}

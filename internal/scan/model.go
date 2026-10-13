package scan

import (
	"time"
)

// Options holds parameters for a scan run
type Options struct {
	Target 	string
	Ports	[]int
	Timeout	time.Duration
	Threads	int
}

// Result describes the outcome of scanning a single port
type Result struct {
	Port	int
	IsOpen	bool
	Banner	string
	OS		string
}

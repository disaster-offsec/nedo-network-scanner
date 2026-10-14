//go:build !linux

package fingerprint

import (
	"errors"
	"net"
)

type stubCollector struct{}

// New returns a Collector for platforms without TCP_INFO support.
func New() Collector {
	return stubCollector{}
}

func (stubCollector) Collect(conn net.Conn) (Fingerprint, error) {
	return Fingerprint{}, errors.New("fingerprint: not supported on this platform")
}

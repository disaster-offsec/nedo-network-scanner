package fingerprint

import "net"

// Collector extracts TCP-level fingerprint data from an established connection.
type Collector interface {
	Collect(conn net.Conn) (Fingerprint, error)
}

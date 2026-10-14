//go:build linux

package fingerprint

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// TCP_INFO option flags (from Linux UAPI, include/uapi/linux/tcp.h).
// x/sys/unix does not export these, so we define them here.
const (
	tcpiOptTimestamps = 1
	tcpiOptSACK       = 2
	tcpiOptWScale     = 4
	tcpiOptECN        = 8
)

type linuxCollector struct{}

// New returns a Collector backed by Linux TCP_INFO.
func New() Collector {
	return linuxCollector{}
}

func (linuxCollector) Collect(conn net.Conn) (Fingerprint, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return Fingerprint{}, errors.New("fingerprint: not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return Fingerprint{}, err
	}

	var info *unix.TCPInfo
	var sockErr error

	controlErr := rawConn.Control(func(fd uintptr) {
		info, sockErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if controlErr != nil {
		return Fingerprint{}, controlErr
	}
	if sockErr != nil {
		return Fingerprint{}, sockErr
	}

	return Fingerprint{
		Window:     int(info.Snd_wnd),
		MSS:        int(info.Snd_mss),
		WScale:     info.Options&tcpiOptWScale != 0,
		SACK:       info.Options&tcpiOptSACK != 0,
		Timestamps: info.Options&tcpiOptTimestamps != 0,
		ECN:        info.Options&tcpiOptECN != 0,
	}, nil
}

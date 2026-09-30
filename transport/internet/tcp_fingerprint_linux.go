//go:build linux

package internet

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func enableSavedSYN(fd uintptr) {
	// Older kernels and non-native sockets may not implement this. Unknown peers
	// deliberately use freedom's configured fallback, rather than breaking ingress.
	_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
}

func ReadTCPFingerprint(conn net.Conn) string {
	profile, _ := ReadTCPFingerprintMetadata(conn)
	return profile
}

func ReadTCPFingerprintMetadata(conn net.Conn) (string, string) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return "", ""
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return "", ""
	}
	var packet [4096]byte
	size := uint32(len(packet))
	var errno syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_TCP, unix.TCP_SAVED_SYN, uintptr(unsafe.Pointer(&packet[0])), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil || errno != 0 || size > uint32(len(packet)) {
		return "", ""
	}
	return ClassifyTCPSYN(packet[:size]), ClassifyTCPSYNECN(packet[:size])
}

//go:build !linux

package internet

import "net"

func enableSavedSYN(uintptr)             {}
func ReadTCPFingerprint(net.Conn) string { return "" }

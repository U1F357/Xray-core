package internet

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// FingerprintedConn carries metadata only to the inbound worker, which immediately
// unwraps it before protocol handling so TLS, splice and syscall type checks survive.
type FingerprintedConn struct {
	net.Conn
	Profile string
}

// ClassifyTCPSYN conservatively identifies common option layouts. It is not an OS
// detector: middleboxes and userspace stacks can generate the same layout.
func ClassifyTCPSYN(packet []byte) string {
	if len(packet) < 20 {
		return ""
	}
	offset := 0
	switch packet[0] >> 4 {
	case 4:
		offset = int(packet[0]&15) * 4
		if offset < 20 || len(packet) < offset || packet[9] != 6 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return ""
		}
	case 6:
		if len(packet) < 40 {
			return ""
		}
		offset = 40
		next := packet[6]
		for next != 6 {
			if offset+2 > len(packet) {
				return ""
			}
			kind := next
			next = packet[offset]
			size := 0
			switch kind {
			case 0, 43, 60:
				size = (int(packet[offset+1]) + 1) * 8
			case 51:
				size = (int(packet[offset+1]) + 2) * 4
			default:
				return ""
			}
			offset += size
			if offset > len(packet) {
				return ""
			}
		}
	default:
		return ""
	}
	if len(packet) < offset+20 {
		return ""
	}
	tcp := packet[offset:]
	length := int(tcp[12]>>4) * 4
	if length < 20 || length > len(tcp) || tcp[13]&0x17 != 2 || binary.BigEndian.Uint16(tcp[14:16]) == 0 {
		return ""
	}
	kinds := []string{}
	scale := -1
	mss := false
	seen := map[byte]bool{}
	for pos := 20; pos < length; {
		kind := tcp[pos]
		kinds = append(kinds, strconv.Itoa(int(kind)))
		if kind == 0 { // EOL padding is not an additional TCP option.
			for _, b := range tcp[pos+1 : length] {
				if b != 0 {
					return ""
				}
			}
			break
		}
		if kind == 1 {
			pos++
			continue
		}
		if pos+2 > length {
			return ""
		}
		size := int(tcp[pos+1])
		if size < 2 || pos+size > length || seen[kind] {
			return ""
		}
		seen[kind] = true
		switch kind {
		case 2:
			if size != 4 || binary.BigEndian.Uint16(tcp[pos+2:pos+4]) == 0 {
				return ""
			}
			mss = true
		case 3:
			if size != 3 || tcp[pos+2] > 14 {
				return ""
			}
			scale = int(tcp[pos+2])
		case 4:
			if size != 2 {
				return ""
			}
		case 8:
			if size != 10 {
				return ""
			}
		}
		pos += size
	}
	if !mss || scale < 0 {
		return ""
	}
	switch strings.Join(kinds, "-") {
	case "2-1-3-1-1-4":
		return "windows"
	case "2-1-3-1-1-8-4-0":
		return "macos"
	case "2-4-8-1-3":
		return "linux"
	}
	return ""
}

type fingerprintCaptureRequestedKey struct{}
type fingerprintCaptureActiveKey struct{}

// ContextWithTCPFingerprintCapture requests SYN capture for eligible TCP listeners.
// Existing listeners are immutable; adding auto outbounds later requires restart.
func ContextWithTCPFingerprintCapture(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, fingerprintCaptureRequestedKey{}, enabled)
}
func TCPFingerprintCaptureRequested(ctx context.Context) bool {
	enabled, _ := ctx.Value(fingerprintCaptureRequestedKey{}).(bool)
	return enabled
}

// ContextWithActiveTCPFingerprintCapture is set only by the raw TCP transport.
func ContextWithActiveTCPFingerprintCapture(ctx context.Context) context.Context {
	return context.WithValue(ctx, fingerprintCaptureActiveKey{}, true)
}
func tcpFingerprintCaptureActive(ctx context.Context) bool {
	enabled, _ := ctx.Value(fingerprintCaptureActiveKey{}).(bool)
	return enabled
}

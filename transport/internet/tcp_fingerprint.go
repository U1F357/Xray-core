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
	RTTUs   uint32
	Profile string
	ECN     string // SYN offer: none, classic, accecn; empty means unavailable/invalid.
}

// tcpSYNHeader validates and extracts the TCP header from a saved IPv4/IPv6 SYN.
func tcpSYNHeader(packet []byte) []byte {
	if len(packet) < 20 {
		return nil
	}
	offset := 0
	switch packet[0] >> 4 {
	case 4:
		offset = int(packet[0]&15) * 4
		if offset < 20 || len(packet) < offset || packet[9] != 6 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return nil
		}
	case 6:
		if len(packet) < 40 {
			return nil
		}
		offset = 40
		next := packet[6]
		for next != 6 {
			if offset+2 > len(packet) {
				return nil
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
				return nil
			}
			offset += size
			if offset > len(packet) {
				return nil
			}
		}
	default:
		return nil
	}
	if len(packet) < offset+20 {
		return nil
	}
	tcp := packet[offset:]
	length := int(tcp[12]>>4) * 4
	if length < 20 || length > len(tcp) || tcp[13]&0x17 != 2 {
		return nil
	}
	return tcp[:length]
}

// ClassifyTCPSYNECN reports the SYN offer, not the negotiated connection mode.
// Unknown and no ECN are distinct, including for unrecognized OS layouts.
func ClassifyTCPSYNECN(packet []byte) string {
	tcp := tcpSYNHeader(packet)
	if tcp == nil || tcp[12]&0x0e != 0 {
		return ""
	}
	switch (tcp[12]&1)<<2 | tcp[13]>>6 {
	case 0:
		return "none"
	case 3:
		return "classic"
	case 7:
		return "accecn"
	default:
		return ""
	}
}

// ClassifyTCPSYN identifies option-layout families, not operating system versions.
func ClassifyTCPSYN(packet []byte) string {
	tcp := tcpSYNHeader(packet)
	if tcp == nil || binary.BigEndian.Uint16(tcp[14:16]) == 0 {
		return ""
	}
	length := len(tcp)
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

type tcpRTTCaptureKey struct{}

func ContextWithTCPRTTCapture(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, tcpRTTCaptureKey{}, enabled)
}
func TCPRTTCaptureRequested(ctx context.Context) bool {
	enabled, _ := ctx.Value(tcpRTTCaptureKey{}).(bool)
	return enabled
}

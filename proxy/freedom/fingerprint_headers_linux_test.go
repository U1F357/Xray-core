//go:build linux

package freedom

import (
	"bytes"
	"encoding/binary"
	"hash/maphash"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func platformPacket4(flags byte) []byte {
	p := make([]byte, 40)
	p[0], p[8], p[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[6:8], 0x4000)
	copy(p[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	binary.BigEndian.PutUint16(p[20:22], 50000)
	binary.BigEndian.PutUint16(p[22:24], 443)
	p[27], p[32], p[33] = 123, 0x50, flags
	return p
}

func TestFingerprintPlatformDefaults(t *testing.T) {
	for _, profile := range []string{"windows", "macos", "linux"} {
		s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}})
		if err := configureFingerprintPlatform(s, profile); err != nil {
			t.Fatal(err)
		}
		want := tcpip.DefaultTTLOption(64)
		if profile == "windows" {
			want = 128
		}
		for _, n := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
			var ttl tcpip.DefaultTTLOption
			if err := s.NetworkProtocolOption(n, &ttl); err != nil || ttl != want {
				t.Fatalf("%s: TTL %d err %v", profile, ttl, err)
			}
		}
		start, end := s.PortManager.PortRange()
		if profile == "linux" {
			if start != 32768 || end != 60999 {
				t.Fatal(start, end)
			}
		} else if start != 49152 || end != 65535 {
			t.Fatal(start, end)
		}
		s.Close()
		s.Wait()
	}
}

func TestFingerprintIPHeaders(t *testing.T) {
	for _, profile := range []string{"windows", "macos", "linux"} {
		t.Run(profile, func(t *testing.T) {
			h := newFingerprintIPHeaders(profile)
			p := platformPacket4(2)
			tcp := append([]byte(nil), p[20:]...)
			h.apply(p)
			first := binary.BigEndian.Uint16(p[4:6])
			if profile == "macos" && first != 0 {
				t.Fatal("macOS atomic IP ID")
			}
			if profile != "macos" && first == 0 {
				t.Fatal("initial ID should be nonzero")
			}
			if !bytes.Equal(tcp, p[20:]) {
				t.Fatal("TCP modified")
			}
			for i := 1; i <= 3; i++ {
				// SYN retransmits and ordinary ACKs consume fresh IPv4 IDs.
				if i > 1 {
					p[33] = 0x10
				}
				h.apply(p)
				got := binary.BigEndian.Uint16(p[4:6])
				if profile != "macos" && got != first+uint16(i) {
					t.Fatal("nonsequential ID", got, first, i)
				}
				var sum uint32
				for j := 0; j < 20; j += 2 {
					sum += uint32(binary.BigEndian.Uint16(p[j : j+2]))
				}
				for sum>>16 != 0 {
					sum = (sum & 65535) + (sum >> 16)
				}
				if sum != 65535 {
					t.Fatal("invalid IPv4 checksum")
				}
			}
			for _, frag := range []uint16{0, 0x2000, 1, 0x4001} {
				p := platformPacket4(2)
				binary.BigEndian.PutUint16(p[6:8], frag)
				before := append([]byte(nil), p...)
				h.apply(p)
				if !bytes.Equal(before, p) {
					t.Fatal("fragmentable packet rewritten")
				}
			}
		})
	}
}

func TestFingerprintFlowLabelAndBounds(t *testing.T) {
	for _, profile := range []string{"macos", "linux"} {
		h := newFingerprintIPHeaders(profile)
		p := make([]byte, 60)
		p[0], p[1], p[5], p[6], p[7] = 0x6a, 0xb0, 20, 6, 64
		p[23], p[39], p[41], p[43] = 1, 2, 100, 80
		body := append([]byte(nil), p[4:]...)
		h.apply(p)
		label := binary.BigEndian.Uint32(p[:4]) & 0xfffff
		if label == 0 || p[0] != 0x6a || p[1]&0xf0 != 0xb0 || !bytes.Equal(body, p[4:]) {
			t.Fatal("invalid flow label rewrite")
		}
		h.apply(p)
		if binary.BigEndian.Uint32(p[:4])&0xfffff != label {
			t.Fatal("unstable flow label")
		}
		// No panic or modification on truncated packets.
		for n := 0; n < len(p); n++ {
			q := append([]byte(nil), p[:n]...)
			before := append([]byte(nil), q...)
			h.apply(q)
			if !bytes.Equal(q, before) {
				t.Fatal("truncated packet modified", n)
			}
		}
	}
	h := newFingerprintIPHeaders("linux")
	for i := 0; i < fingerprintIDCacheLimit+10; i++ {
		p := platformPacket4(2)
		binary.BigEndian.PutUint32(p[16:20], uint32(i))
		h.apply(p)
	}
	if len(h.flows) != fingerprintIDCacheLimit || h.lru.Len() != fingerprintIDCacheLimit {
		t.Fatal("unbounded ID cache")
	}
}

func TestFingerprintLinuxIDsAreIndependentAndWrap(t *testing.T) {
	h := newFingerprintIPHeaders("linux")
	a, b := platformPacket4(2), platformPacket4(2)
	binary.BigEndian.PutUint16(b[20:22], 50001)
	h.apply(a)
	first := binary.BigEndian.Uint16(a[4:6])
	h.apply(b)
	h.apply(a)
	if binary.BigEndian.Uint16(a[4:6]) != first+1 {
		t.Fatal("another flow changed the sequence")
	}
	var key [12]byte
	copy(key[:8], a[12:20])
	copy(key[8:], a[20:24])
	h.flows[key].Value.(*fingerprintIDFlow).next = 65535
	a[33] = 0x14 // RST+ACK still receives an ordinary IP ID; flags stay intact.
	h.apply(a)
	if binary.BigEndian.Uint16(a[4:6]) != 65535 || a[33] != 0x14 {
		t.Fatal("RST or IP ID changed incorrectly")
	}
	h.apply(a)
	if binary.BigEndian.Uint16(a[4:6]) != 0 {
		t.Fatal("IP ID did not wrap")
	}
	a[27]++
	a[33] = 2
	h.apply(a)
	var initial [16]byte
	copy(initial[:12], key[:])
	copy(initial[12:], a[24:28])
	want := uint16(maphash.Bytes(h.seed, initial[:])%65535 + 1)
	if binary.BigEndian.Uint16(a[4:6]) != want {
		t.Fatal("new connection did not reinitialize IP ID")
	}
}

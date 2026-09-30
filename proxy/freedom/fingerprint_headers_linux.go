//go:build linux

package freedom

import (
	"container/list"
	"encoding/binary"
	"hash/maphash"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// These are platform-family presets, not replicas of a particular OS release.
// TCP state, flags, congestion control and retransmissions remain in netstack.
func configureFingerprintPlatform(s *stack.Stack, profile string) tcpip.Error {
	ttl := tcpip.DefaultTTLOption(64)
	start, end := uint16(49152), uint16(65535)
	if profile == "windows" {
		ttl = 128
	}
	if profile == "linux" {
		start, end = 32768, 60999
	}
	for _, protocol := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
		if err := s.SetNetworkProtocolOption(protocol, &ttl); err != nil {
			return err
		}
	}
	if err := s.SetPortRange(start, end); err != nil {
		return err
	}
	return nil
}

const fingerprintIDCacheLimit = 65536

type fingerprintIDFlow struct {
	key         [12]byte // IPv4 addresses and TCP ports, before NAT.
	next        uint16
	synSequence uint32
	hasSYN      bool
}

// fingerprintIPHeaders is owned exclusively by the TUN write pump. The cache
// bounds memory even when scans never complete a handshake. Eviction can change
// an atomic datagram's ID sequence, but not TCP semantics (RFC 6864).
// Never rewrite IDs of fragments or packets for which fragmentation is allowed.
type fingerprintIPHeaders struct {
	profile   string
	seed      maphash.Seed
	windowsID uint16
	flows     map[[12]byte]*list.Element
	lru       list.List
}

func newFingerprintIPHeaders(profile string) *fingerprintIPHeaders {
	seed := maphash.MakeSeed()
	return &fingerprintIPHeaders{profile: profile, seed: seed, windowsID: uint16(maphash.String(seed, "ipv4-id")%65535 + 1), flows: make(map[[12]byte]*list.Element)}
}

func (h *fingerprintIPHeaders) apply(p []byte) {
	if len(p) < 20 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		n := int(p[0]&15) * 4
		if n < 20 || len(p) < n+20 || p[9] != 6 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			return
		}
		if binary.BigEndian.Uint16(p[6:8]) != 0x4000 {
			return
		}
		var id uint16
		switch h.profile {
		case "windows":
			id = h.windowsID
			h.windowsID++
		case "linux":
			var key [12]byte
			copy(key[:8], p[12:20])
			copy(key[8:], p[n:n+4])
			e := h.flows[key]
			if e == nil {
				if len(h.flows) == fingerprintIDCacheLimit {
					old := h.lru.Back()
					delete(h.flows, old.Value.(*fingerprintIDFlow).key)
					h.lru.Remove(old)
				}
				e = h.lru.PushFront(&fingerprintIDFlow{key: key, next: uint16(maphash.Bytes(h.seed, key[:])%65535 + 1)})
				h.flows[key] = e
			}
			h.lru.MoveToFront(e)
			f := e.Value.(*fingerprintIDFlow)
			if p[n+13]&0x12 == 0x02 {
				seq := binary.BigEndian.Uint32(p[n+4 : n+8])
				if !f.hasSYN || f.synSequence != seq {
					var initial [16]byte
					copy(initial[:12], key[:])
					binary.BigEndian.PutUint32(initial[12:], seq)
					f.next = uint16(maphash.Bytes(h.seed, initial[:])%65535 + 1)
					f.synSequence, f.hasSYN = seq, true
				}
			}
			id = f.next
			f.next++
		case "macos":
			// Current XNU defaults rfc6864=1: zero ID for atomic IPv4 datagrams.
			id = 0
		default:
			return
		}
		binary.BigEndian.PutUint16(p[4:6], id)
		p[10], p[11] = 0, 0
		var sum uint32
		for i := 0; i < n; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	case 6:
		if len(p) < 60 || p[6] != 6 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) {
			return
		}
		if h.profile != "linux" && h.profile != "macos" {
			return
		}
		// A stable, secret-keyed per-flow label. No payload/TCP checksum changes:
		// the flow label is not part of the IPv6 transport pseudo-header.
		label := uint32(maphash.Bytes(h.seed, p[8:44])%0xfffff + 1)
		word := binary.BigEndian.Uint32(p[:4])
		binary.BigEndian.PutUint32(p[:4], word&0xfff00000|label)
	}
}

// Packet-level ECN tests use an in-memory link; no host networking privileges.
package ecn_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type peer struct {
	t             *testing.T
	link          *channel.Endpoint
	proto         tcpip.NetworkProtocolNumber
	local, remote tcpip.Address
	port          uint16
	seq, ack      uint32
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func (p *peer) read() ([]byte, byte) {
	p.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	for {
		pkt := p.link.ReadContext(ctx)
		if pkt == nil {
			p.t.Fatal("timeout waiting for TCP packet")
		}
		v := pkt.ToView()
		b := append([]byte(nil), v.AsSlice()...)
		v.Release()
		pkt.DecRef()
		offset := 20
		tc := b[1]
		if b[0]>>4 == 6 {
			if b[6] != 6 {
				continue
			}
			offset = 40
			tc = (b[0]&15)<<4 | b[1]>>4
		} else {
			if b[9] != 6 {
				continue
			}
			offset = int(b[0]&15) * 4
		}
		h := b[offset:]
		return h, tc
	}
}
func (p *peer) send(flags, ecn byte, data []byte) { p.sendAE(flags, false, ecn, data) }
func (p *peer) sendAE(flags byte, ae bool, ecn byte, data []byte) {
	p.t.Helper()
	headerLen := 20
	if flags&2 != 0 {
		headerLen = 24
	}
	h := make([]byte, headerLen+len(data))
	binary.BigEndian.PutUint16(h, 80)
	binary.BigEndian.PutUint16(h[2:], p.port)
	binary.BigEndian.PutUint32(h[4:], p.seq)
	binary.BigEndian.PutUint32(h[8:], p.ack)
	h[12] = byte(headerLen/4) << 4
	if ae {
		h[12] |= 1
	}
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:], 65535)
	if headerLen == 24 {
		copy(h[20:24], []byte{4, 2, 1, 1})
	}
	copy(h[headerLen:], data)
	pseudo := append(append([]byte{}, p.remote.AsSlice()...), p.local.AsSlice()...)
	var ip []byte
	if p.proto == ipv4.ProtocolNumber {
		pseudo = append(pseudo, 0, 6, byte(len(h)>>8), byte(len(h)))
		ip = make([]byte, 20)
		ip[0] = 0x45
		ip[1] = ecn
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(h)))
		ip[6] = 0x40
		ip[8] = 64
		ip[9] = 6
		copy(ip[12:], p.remote.AsSlice())
		copy(ip[16:], p.local.AsSlice())
		binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	} else {
		pseudo = append(pseudo, 0, 0, byte(len(h)>>8), byte(len(h)), 0, 0, 0, 6)
		ip = make([]byte, 40)
		ip[0] = 0x60
		ip[1] = ecn << 4
		binary.BigEndian.PutUint16(ip[4:], uint16(len(h)))
		ip[6] = 6
		ip[7] = 64
		copy(ip[8:], p.remote.AsSlice())
		copy(ip[24:], p.local.AsSlice())
	}
	binary.BigEndian.PutUint16(h[16:], checksum(append(pseudo, h...)))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append(ip, h...))})
	p.link.InjectInbound(p.proto, pkt)
	pkt.DecRef()
	p.seq += uint32(len(data))
	if flags&2 != 0 {
		p.seq++
	}
}

type handshakeOptions struct {
	mode                    tcpip.TCPFingerprintECNOption
	responseACE, synACKMark byte
}

func open(t *testing.T, profile tcpip.TCPFingerprintProfile, v6, accept, fallback bool, options ...handshakeOptions) (*peer, *gonet.TCPConn) {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	link := channel.New(128, 1500, "")
	t.Cleanup(func() { s.Close(); s.Wait(); link.Close() })
	if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &profile); e != nil {
		t.Fatal(e)
	}
	if e := s.CreateNIC(1, link); e != nil {
		t.Fatal(e)
	}
	p := &peer{t: t, link: link, proto: ipv4.ProtocolNumber, local: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), remote: tcpip.AddrFrom4([4]byte{192, 0, 2, 2}), seq: 1000}
	subnet := header.IPv4EmptySubnet
	if v6 {
		p.proto = ipv6.ProtocolNumber
		p.local = tcpip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		p.remote = tcpip.AddrFrom16([16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		subnet = header.IPv6EmptySubnet
	}
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: p.proto, AddressWithPrefix: p.local.WithPrefix()}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
	type result struct {
		c   *gonet.TCPConn
		err error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	go func() {
		if len(options) == 0 {
			c, e := gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: p.remote, Port: 80}, p.proto)
			done <- result{c, e}
			return
		}
		var wq waiter.Queue
		ep, e := s.NewEndpoint(tcp.ProtocolNumber, p.proto, &wq)
		if e != nil {
			done <- result{nil, fmt.Errorf("endpoint: %s", e)}
			return
		}
		mode := options[0].mode
		if e = ep.SetSockOpt(&mode); e != nil {
			ep.Close()
			done <- result{nil, fmt.Errorf("option: %s", e)}
			return
		}
		entry, ready := waiter.NewChannelEntry(waiter.WritableEvents)
		wq.EventRegister(&entry)
		defer wq.EventUnregister(&entry)
		e = ep.Connect(tcpip.FullAddress{NIC: 1, Addr: p.remote, Port: 80})
		if _, pending := e.(*tcpip.ErrConnectStarted); pending {
			select {
			case <-ctx.Done():
				ep.Close()
				done <- result{nil, ctx.Err()}
				return
			case <-ready:
			}
			e = ep.LastError()
		}
		if e != nil {
			ep.Close()
			done <- result{nil, fmt.Errorf("connect: %s", e)}
			return
		}
		if ep.SetSockOpt(&mode) == nil {
			ep.Close()
			done <- result{nil, fmt.Errorf("accepted ECN mode change after Connect")}
			return
		}
		done <- result{gonet.NewTCPConn(&wq, ep), nil}
	}()
	syn, tc := p.read()
	wantFlags, wantTC := byte(2), byte(0)
	custom := profile == tcpip.TCPFingerprintWindows || profile == tcpip.TCPFingerprintMacOS
	if custom {
		wantFlags = 0xc2
		if profile == tcpip.TCPFingerprintWindows {
			wantTC = 2
		}
	}
	wantAE := false
	if len(options) > 0 {
		mode := options[0].mode
		if mode == tcpip.TCPFingerprintECNNone {
			wantFlags, wantTC = 2, 0
		}
		if mode == tcpip.TCPFingerprintECNClassic || mode == tcpip.TCPFingerprintECNAccurate {
			wantFlags = 0xc2
			wantTC = 0
			if profile == tcpip.TCPFingerprintWindows {
				wantTC = 2
			}
			if mode == tcpip.TCPFingerprintECNAccurate {
				wantAE = true
				if profile == tcpip.TCPFingerprintMacOS {
					wantTC = 1
				}
			}
		}
	}
	if (syn[12]&1 != 0) != wantAE {
		t.Fatalf("SYN AE=%v want %v", syn[12]&1 != 0, wantAE)
	}
	if syn[13] != wantFlags || tc != wantTC {
		t.Fatalf("SYN flags=%#x TC=%#x, want %#x/%#x", syn[13], tc, wantFlags, wantTC)
	}
	if fallback {
		syn, tc = p.read()
		if syn[13] != 2 || tc != 0 {
			t.Fatalf("fallback SYN flags=%#x TC=%#x", syn[13], tc)
		}
	}
	p.port = binary.BigEndian.Uint16(syn)
	p.ack = binary.BigEndian.Uint32(syn[4:]) + 1
	flags := byte(0x12)
	if accept {
		flags |= 0x40
	}
	thirdACE := byte(0)
	if len(options) > 0 {
		o := options[0]
		flags = 0x12 | (o.responseACE&3)<<6
		p.sendAE(flags, o.responseACE&4 != 0, o.synACKMark, nil)
		if o.mode == tcpip.TCPFingerprintECNAccurate && !fallback && o.responseACE >= 2 && o.responseACE <= 6 {
			thirdACE = [4]byte{2, 3, 4, 6}[o.synACKMark]
		}
	} else {
		p.send(flags, 0, nil)
	}
	ack, tc := p.read()
	if ack[13] != 0x10|(thirdACE&3)<<6 || (ack[12]&1 != 0) != (thirdACE&4 != 0) || tc != 0 {
		t.Fatalf("third ACK flags=%#x TC=%#x", ack[13], tc)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { r.c.Close() })
	return p, r.c
}
func TestClassicECNWire(t *testing.T) {
	for _, profile := range []tcpip.TCPFingerprintProfile{tcpip.TCPFingerprintWindows, tcpip.TCPFingerprintMacOS, tcpip.TCPFingerprintLinux, 0} {
		for _, v6 := range []bool{false, true} {
			for _, accept := range []bool{false, true} {
				t.Run(fmt.Sprintf("profile%d/v6%v/peerECN%v", profile, v6, accept), func(t *testing.T) {
					p, c := open(t, profile, v6, accept, false)
					enabled := accept && (profile == tcpip.TCPFingerprintWindows || profile == tcpip.TCPFingerprintMacOS)
					if _, err := c.Write([]byte("hello")); err != nil {
						t.Fatal(err)
					}
					h, tc := p.read()
					wantTC := byte(0)
					if enabled {
						wantTC = 2
					}
					if tc != wantTC {
						t.Fatalf("data TC=%#x want %#x", tc, wantTC)
					}
					p.ack = binary.BigEndian.Uint32(h[4:]) + uint32(len(h)-int(h[12]>>4)*4)
					// Mark peer data CE; ACK must echo ECE only after successful negotiation.
					p.send(0x58, 3, []byte("a"))
					h, tc = p.read()
					if (h[13]&0x40 != 0) != enabled || tc != 0 {
						t.Fatalf("CE feedback flags=%#x TC=%#x enabled=%v", h[13], tc, enabled)
					}
					// ACK the sent data with ECE and clear our receiver's ECE using CWR.
					p.send(0xd8, 0, []byte("b"))
					h, tc = p.read()
					if h[13]&0x40 != 0 || tc != 0 {
						t.Fatalf("CWR did not clear echo: %#x/%#x", h[13], tc)
					}
					if _, err := c.Write([]byte("next")); err != nil {
						t.Fatal(err)
					}
					h, tc = p.read()
					if (h[13]&0x80 != 0) != enabled || tc != wantTC {
						t.Fatalf("sender CWR flags=%#x TC=%#x enabled=%v", h[13], tc, enabled)
					}
				})
			}
		}
	}
}
func TestClassicECNSYNTimeout(t *testing.T) {
	for _, profile := range []tcpip.TCPFingerprintProfile{tcpip.TCPFingerprintWindows, tcpip.TCPFingerprintMacOS} {
		for _, v6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("profile%d/v6%v", profile, v6), func(t *testing.T) {
				p, c := open(t, profile, v6, false, true)
				if _, err := c.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				_, tc := p.read()
				if tc != 0 {
					t.Fatal("fallback data is ECT")
				}
			})
		}
	}
}

func TestClassicECNDataRetransmission(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v6%v", v6), func(t *testing.T) {
			p, c := open(t, tcpip.TCPFingerprintWindows, v6, true, false)
			if _, err := c.Write([]byte("lost")); err != nil {
				t.Fatal(err)
			}
			original, tc := p.read()
			if tc != 2 {
				t.Fatalf("new data TC=%#x", tc)
			}
			retrans, tc := p.read()
			if tc != 0 || retrans[13]&0x80 != 0 || binary.BigEndian.Uint32(original[4:]) != binary.BigEndian.Uint32(retrans[4:]) {
				t.Fatalf("retransmission must be Not-ECT, without CWR: flags=%#x TC=%#x", retrans[13], tc)
			}
			p.ack = binary.BigEndian.Uint32(retrans[4:]) + uint32(len(retrans)-int(retrans[12]>>4)*4)
			p.send(0x18, 0, []byte("reply"))
			p.read()
			if _, err := c.Write([]byte("after recovery")); err != nil {
				t.Fatal(err)
			}
			h, tc := p.read()
			if tc != 2 {
				t.Fatalf("new data after recovery TC=%#x", tc)
			}
			// The connection must still deliver peer data after the lost segment.
			buf := make([]byte, 5)
			if _, err := c.Read(buf); err != nil || string(buf) != "reply" {
				t.Fatalf("read=%q err=%v", buf, err)
			}
			_ = h
		})
	}
}

func ace(h []byte) byte { return (h[12]&1)<<2 | h[13]>>6 }

func TestAccECNNegotiation(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for code := byte(0); code < 8; code++ {
			for mark := byte(0); mark < 4; mark++ {
				t.Run(fmt.Sprintf("v6%v/reply%d/mark%d", v6, code, mark), func(t *testing.T) {
					p, c := open(t, tcpip.TCPFingerprintMacOS, v6, false, false, handshakeOptions{tcpip.TCPFingerprintECNAccurate, code, mark})
					if _, err := c.Write([]byte("hello")); err != nil {
						t.Fatal(err)
					}
					h, tc := p.read()
					accurate := code >= 2 && code <= 6
					wantTC := byte(0)
					if code == 1 || code == 3 || code == 5 || code == 6 {
						wantTC = 2
					}
					if tc != wantTC {
						t.Fatalf("data TC=%d want %d", tc, wantTC)
					}
					if accurate {
						want := byte(5)
						if mark == 3 {
							want = 6
						}
						if ace(h) != want {
							t.Fatalf("ACE=%d want %d", ace(h), want)
						}
					} else if ace(h) != 0 {
						t.Fatalf("fallback data ACE=%d", ace(h))
					}
				})
			}
		}
	}
}

func TestAccECNReceiverCounter(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v6%v", v6), func(t *testing.T) {
			p, c := open(t, tcpip.TCPFingerprintMacOS, v6, false, false, handshakeOptions{tcpip.TCPFingerprintECNAccurate, 3, 0})
			for n := 1; n <= 12; n++ {
				// The peer sends ACE=5 (no congestion on our data) and CE-marked data.
				p.sendAE(0x58, true, 3, []byte{byte(n)})
				h, tc := p.read()
				want := byte((5 + n) & 7)
				if ace(h) != want || tc != 0 {
					t.Fatalf("CE #%d: ACE=%d TC=%d want %d/0", n, ace(h), tc, want)
				}
				b := make([]byte, 1)
				if _, err := c.Read(b); err != nil || b[0] != byte(n) {
					t.Fatalf("read=%v err=%v", b, err)
				}
			}
			// Pure CE ACKs must trigger feedback after three, not an ACK loop.
			for n := 0; n < 3; n++ {
				p.sendAE(0x50, true, 3, nil)
			}
			h, tc := p.read()
			if ace(h) != 4 || tc != 0 {
				t.Fatalf("ACK of CE ACKs ACE=%d TC=%d", ace(h), tc)
			}
		})
	}
}

func TestAccECNDSACKAndRepeatedSYNACK(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("v6%v", v6), func(t *testing.T) {
			p, c := open(t, tcpip.TCPFingerprintMacOS, v6, false, false, handshakeOptions{tcpip.TCPFingerprintECNAccurate, 3, 0})
			originalSeq := p.seq
			p.sendAE(0x58, true, 3, []byte("x"))
			p.read()
			b := make([]byte, 1)
			if _, err := c.Read(b); err != nil {
				t.Fatal(err)
			}
			p.seq = originalSeq
			p.sendAE(0x58, true, 0, []byte("x"))
			h, _ := p.read()
			opts := header.ParseTCPOptions(h[20 : int(h[12]>>4)*4])
			if len(opts.SACKBlocks) == 0 || uint32(opts.SACKBlocks[0].Start) != originalSeq || uint32(opts.SACKBlocks[0].End) != originalSeq+1 {
				t.Fatalf("missing D-SACK: %+v", opts.SACKBlocks)
			}
			// The retransmitted SYN/ACK must use the handshake encoding, while a CE
			// SYN/ACK is counted no more than once across retransmissions.
			nextSeq := p.seq
			for i := 0; i < 2; i++ {
				p.seq = 1000
				p.sendAE(0xd2, false, 3, nil)
				h, _ = p.read()
				if ace(h) != 6 {
					t.Fatalf("repeated SYNACK response ACE=%d", ace(h))
				}
			}
			p.seq = nextSeq
			p.sendAE(0x58, true, 0, []byte("y"))
			h, _ = p.read()
			if ace(h) != 7 {
				t.Fatalf("SYNACK CE counted more than once: ACE=%d", ace(h))
			}
		})
	}
}

func TestAccECNACKOfACKOmitsSACK(t *testing.T) {
	p, _ := open(t, tcpip.TCPFingerprintMacOS, false, false, false, handshakeOptions{tcpip.TCPFingerprintECNAccurate, 3, 0})
	p.seq += 10
	p.sendAE(0x58, true, 3, []byte("x"))
	h, _ := p.read()
	opts := header.ParseTCPOptions(h[20 : int(h[12]>>4)*4])
	if len(opts.SACKBlocks) == 0 {
		t.Fatal("missing SACK for out-of-order data")
	}
	for n := 0; n < 3; n++ {
		p.sendAE(0x50, true, 3, nil)
	}
	h, _ = p.read()
	opts = header.ParseTCPOptions(h[20 : int(h[12]>>4)*4])
	if len(opts.SACKBlocks) != 0 {
		t.Fatal("ACK of ACK must not carry SACK")
	}
	if ace(h) != 1 {
		t.Fatalf("ACE=%d want 1", ace(h))
	}
}

func TestAccECNPartialOutOfOrderDSACK(t *testing.T) {
	p, _ := open(t, tcpip.TCPFingerprintMacOS, false, false, false, handshakeOptions{tcpip.TCPFingerprintECNAccurate, 3, 0})
	start := p.seq + 10
	p.seq = start
	p.sendAE(0x58, true, 0, []byte("abcde"))
	p.read()
	p.seq = start + 2
	p.sendAE(0x58, true, 0, []byte("cdefg"))
	h, _ := p.read()
	opts := header.ParseTCPOptions(h[20 : int(h[12]>>4)*4])
	if len(opts.SACKBlocks) < 2 {
		t.Fatal("missing duplicate/containing SACK pair")
	}
	dup, containing := opts.SACKBlocks[0], opts.SACKBlocks[1]
	if uint32(dup.Start) != start+2 || uint32(dup.End) != start+5 || uint32(containing.Start) != start || uint32(containing.End) != start+7 {
		t.Fatalf("D-SACK=%+v containing=%+v", dup, containing)
	}
}

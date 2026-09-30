//go:build linux

package freedom

import (
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"net/netip"
	"os"
	"sync"
	"time"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/freedom/fingerprintnet"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type tunFingerprintDialer struct {
	ecnMode   string
	profile   string
	headers   *fingerprintIPHeaders
	routeMu   sync.Mutex
	mtu       uint32
	subnet    tcpip.Subnet
	stack     *stack.Stack
	file      *os.File
	link      *channel.Endpoint
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	dialing   sync.WaitGroup
	pumps     sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
	automatic *fingerprintnet.Network
}

func newFingerprintDialerFamily(c *Config, is6 bool) (fingerprintDialer, error) {
	if err := ValidateTCPFingerprint(c); err != nil {
		return nil, err
	}
	settings := c.TcpFingerprintSettings
	var file *os.File
	var automatic *fingerprintnet.Network
	var mtu uint32
	var addr netip.Addr
	if settings == nil {
		var err error
		if is6 {
			automatic, err = fingerprintnet.PrepareIPv6()
		} else {
			automatic, err = fingerprintnet.Prepare()
		}
		if err != nil {
			return nil, err
		}
		file, mtu = automatic.File, automatic.MTU
		addr = netip.MustParseAddr(automatic.Address)
	} else {
		iface, err := net.InterfaceByName(settings.Tun)
		if err != nil {
			return nil, fmt.Errorf("tcpFingerprint: preconfigure TUN %q first: %w", settings.Tun, err)
		}
		if iface.Flags&stdnet.FlagUp == 0 {
			return nil, fmt.Errorf("tcpFingerprint: TUN %q is down", settings.Tun)
		}
		addr = netip.MustParseAddr(settings.Address)
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, local := range addresses {
			prefix, err := netip.ParsePrefix(local.String())
			if err == nil && prefix.Addr() == addr {
				return nil, fmt.Errorf("tcpFingerprint address must differ from the host TUN address")
			}
		}
		mtu, err = rawfile.GetMTU(settings.Tun)
		if err != nil {
			return nil, err
		}
		fd, err := tun.Open(settings.Tun)
		if err != nil {
			return nil, fmt.Errorf("tcpFingerprint: open TUN: %w", err)
		}
		// Own the packet I/O lifecycle explicitly. A nonblocking TUN wrapped in
		// os.File uses Go's poller, so Close interrupts a pending Read or Write.
		file = os.NewFile(uintptr(fd), settings.Tun)
	}
	link := channel.New(1024, mtu, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	lifetime, cancel := context.WithCancel(context.Background())
	d := &tunFingerprintDialer{ecnMode: c.TcpEcn, profile: c.TcpFingerprint, stack: s, file: file, link: link, ctx: lifetime, cancel: cancel, automatic: automatic, mtu: mtu, headers: newFingerprintIPHeaders(c.TcpFingerprint)}
	ok := false
	defer func() {
		if !ok {
			d.Close()
		}
	}()
	profiles := map[string]tcpip.TCPFingerprintProfile{
		"windows": tcpip.TCPFingerprintWindows,
		"macos":   tcpip.TCPFingerprintMacOS,
		"linux":   tcpip.TCPFingerprintLinux,
	}
	profile := profiles[c.TcpFingerprint]
	if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &profile); e != nil {
		return nil, fmt.Errorf("tcpFingerprint: %s", e)
	}
	if err := configureFingerprintPlatform(s, c.TcpFingerprint); err != nil {
		return nil, fmt.Errorf("tcpFingerprint platform: %s", err)
	}
	if e := s.CreateNIC(1, link); e != nil {
		return nil, fmt.Errorf("tcpFingerprint NIC: %s", e)
	}
	protocol := ipv4.ProtocolNumber
	subnet := header.IPv4EmptySubnet
	if addr.Is6() {
		if mtu < 1280 {
			return nil, fmt.Errorf("IPv6 TCP fingerprint requires TUN MTU >= 1280")
		}
		protocol = ipv6.ProtocolNumber
		subnet = header.IPv6EmptySubnet
	}
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix()}, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("tcpFingerprint address: %s", e)
	}
	d.subnet = subnet
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})
	d.pumps.Add(2)
	go d.readPackets()
	go d.writePackets()
	ok = true
	return d, nil
}

func (d *tunFingerprintDialer) readPackets() {
	defer d.pumps.Done()
	data := make([]byte, 65535)
	for {
		n, err := d.file.Read(data)
		if err != nil {
			go d.Close()
			return
		}
		if n == 0 {
			continue
		}
		protocol := ipv4.ProtocolNumber
		switch data[0] >> 4 {
		case 4:
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data[:n])})
		d.link.InjectInbound(protocol, packet)
		packet.DecRef()
	}
}

func (d *tunFingerprintDialer) writePackets() {
	defer d.pumps.Done()
	for {
		packet := d.link.ReadContext(d.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		packet.DecRef()
		d.headers.apply(view.AsSlice())
		_, err := d.file.Write(view.AsSlice())
		view.Release()
		if err != nil {
			go d.Close()
			return
		}
	}
}

func (d *tunFingerprintDialer) Dial(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if dest.Network != net.Network_TCP || !dest.Address.Family().IsIP() {
		return nil, fmt.Errorf("tcpFingerprint requires a resolved IP TCP destination")
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, os.ErrClosed
	}
	d.dialing.Add(1)
	d.mu.Unlock()
	defer d.dialing.Done()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	mtu := d.mtu
	if d.automatic != nil {
		var err error
		mtu, err = d.automatic.PrepareDestinationMTU(ctx, dest.Address.IP().String())
		if err != nil {
			return nil, err
		}
	}
	ip := dest.Address.IP().To4()
	protocol := ipv4.ProtocolNumber
	if ip == nil {
		ip = dest.Address.IP().To16()
		protocol = ipv6.ProtocolNumber
	}
	minimum, overhead := uint32(88), uint32(40)
	if protocol == ipv6.ProtocolNumber {
		minimum, overhead = 1280, 60
	}
	if mtu < minimum || mtu > d.mtu {
		return nil, fmt.Errorf("invalid route MTU %d for fingerprint network", mtu)
	}
	xerrors.LogInfo(ctx, "TCP fingerprint MTU: target=", dest, " routeMTU=", mtu, " synMSS=", mtu-overhead)
	return d.dialWithMTU(ctx, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip), Port: uint16(dest.Port)}, protocol, mtu)
}

func (d *tunFingerprintDialer) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.cancel()
		d.mu.Unlock()
		d.closeErr = d.file.Close()
		d.dialing.Wait()
		d.pumps.Wait()
		d.stack.Close()
		d.stack.Wait()
		d.link.Close()
		if d.automatic != nil {
			d.closeErr = errors.Join(d.closeErr, d.automatic.Close())
		}
	})
	return d.closeErr
}

// IPv6 is prepared on first use: IPv4-only hosts do not need IPv6 forwarding
// or IPv6 nftables support just to start an existing configuration.
type dualFingerprintDialer struct {
	mu     sync.Mutex
	config *Config
	v4, v6 fingerprintDialer
	closed bool
}

func newFingerprintDialer(c *Config) (fingerprintDialer, error) {
	if c.TcpFingerprintSettings != nil {
		return newFingerprintDialerFamily(c, false)
	}
	v4, err := newFingerprintDialerFamily(c, false)
	if err != nil {
		return nil, err
	}
	return &dualFingerprintDialer{config: c, v4: v4}, nil
}
func (d *dualFingerprintDialer) Dial(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, os.ErrClosed
	}
	chosen := d.v4
	if dest.Address.Family().IsIPv6() {
		ip := dest.Address.IP()
		if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
			d.mu.Unlock()
			return nil, fmt.Errorf("tcpFingerprint IPv6 destination must be routable unicast without a zone")
		}
		if d.v6 == nil {
			var err error
			d.v6, err = newFingerprintDialerFamily(d.config, true)
			if err != nil {
				d.mu.Unlock()
				return nil, err
			}
		}
		chosen = d.v6
	}
	d.mu.Unlock()
	return chosen.Dial(ctx, dest)
}
func (d *dualFingerprintDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	err := d.v4.Close()
	if d.v6 != nil {
		err = errors.Join(err, d.v6.Close())
	}
	return err
}

// Connect captures an immutable stack.Route synchronously. Serialize just that
// operation with the temporary route MTU; handshake waits remain concurrent.
// Existing endpoints keep their own route and are never resized by another dial.
func (d *tunFingerprintDialer) dialWithMTU(ctx context.Context, address tcpip.FullAddress, protocol tcpip.NetworkProtocolNumber, mtu uint32) (net.Conn, error) {
	var wq waiter.Queue
	ep, err := d.stack.NewEndpoint(tcp.ProtocolNumber, protocol, &wq)
	if err != nil {
		return nil, fmt.Errorf("fingerprint endpoint: %s", err)
	}
	success := false
	defer func() {
		if !success {
			ep.Close()
		}
	}()
	entry, ready := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mode, source, fallback := selectFingerprintECN(ctx, d.ecnMode, d.profile)
	option := map[string]tcpip.TCPFingerprintECNOption{"none": tcpip.TCPFingerprintECNNone, "classic": tcpip.TCPFingerprintECNClassic, "accecn": tcpip.TCPFingerprintECNAccurate}[mode]
	if err := ep.SetSockOpt(&option); err != nil {
		return nil, fmt.Errorf("fingerprint ECN: %s", err)
	}
	xerrors.LogInfo(ctx, "TCP ECN freedom: selected=", mode, " source=", source, " fallback=", fallback, " profile=", d.profile)
	d.routeMu.Lock()
	d.stack.SetRouteTable([]tcpip.Route{{Destination: d.subnet, NIC: 1, MTU: mtu}})
	err = ep.Connect(address)
	d.stack.SetRouteTable([]tcpip.Route{{Destination: d.subnet, NIC: 1}})
	d.routeMu.Unlock()
	if _, pending := err.(*tcpip.ErrConnectStarted); pending {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
		}
		err = ep.LastError()
	}
	if err != nil {
		return nil, fmt.Errorf("fingerprint connect: %s", err)
	}
	success = true
	return gonet.NewTCPConn(&wq, ep), nil
}

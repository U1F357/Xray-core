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
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

type tunFingerprintDialer struct {
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

func newFingerprintDialer(c *Config) (fingerprintDialer, error) {
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
		automatic, err = fingerprintnet.Prepare()
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, icmp.NewProtocol4},
	})
	lifetime, cancel := context.WithCancel(context.Background())
	d := &tunFingerprintDialer{stack: s, file: file, link: link, ctx: lifetime, cancel: cancel, automatic: automatic}
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
	if e := s.CreateNIC(1, link); e != nil {
		return nil, fmt.Errorf("tcpFingerprint NIC: %s", e)
	}
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(addr.As4()).WithPrefix()}, stack.AddressProperties{}); e != nil {
		return nil, fmt.Errorf("tcpFingerprint address: %s", e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
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
		if n == 0 || data[0]>>4 != 4 {
			continue
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data[:n])})
		d.link.InjectInbound(ipv4.ProtocolNumber, packet)
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
		_, err := d.file.Write(view.AsSlice())
		view.Release()
		if err != nil {
			go d.Close()
			return
		}
	}
}

func (d *tunFingerprintDialer) Dial(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if dest.Network != net.Network_TCP || !dest.Address.Family().IsIPv4() {
		return nil, fmt.Errorf("tcpFingerprint requires a resolved IPv4 TCP destination")
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
	if d.automatic != nil {
		if err := d.automatic.PrepareDestination(ctx, dest.Address.String()); err != nil {
			return nil, err
		}
	}
	return gonet.DialContextTCP(ctx, d.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dest.Address.IP().To4()), Port: uint16(dest.Port)}, ipv4.ProtocolNumber)
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

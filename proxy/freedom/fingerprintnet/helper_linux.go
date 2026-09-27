//go:build linux

package fingerprintnet

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != helperArgument {
		return
	}
	if err := serveHelper(); err != nil {
		fmt.Fprintln(os.Stderr, "tcpFingerprint network helper:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

type environment struct {
	token      string
	owner      owner
	file       *os.File
	mtu        uint32
	interfaces map[int]string
}

func writeReply(c *net.UnixConn, reply message, file *os.File) error {
	b, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	var rights []byte
	if file != nil {
		raw, err := file.SyscallConn()
		if err != nil {
			return err
		}
		if err := raw.Control(func(fd uintptr) { rights = unix.UnixRights(int(fd)) }); err != nil {
			return err
		}
	}
	_, _, err = c.WriteMsgUnix(b, rights, nil)
	return err
}

func serveHelper() error {
	control, err := unixConn(os.NewFile(3, "fingerprint-control"))
	if err != nil {
		return err
	}
	defer control.Close()
	// EOF also handles SIGKILL of the parent. Keep this process in its own
	// session so service/process-group shutdown cannot skip cleanup.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-signals:
			control.Close()
		case <-done:
		}
	}()
	env, err := prepareEnvironment()
	if err != nil {
		writeReply(control, message{Error: err.Error()}, nil)
		return nil
	}
	defer env.file.Close()
	cleaned := false
	defer func() {
		if !cleaned {
			if err := env.cleanup(); err != nil {
				fmt.Fprintln(os.Stderr, "tcpFingerprint cleanup:", err)
			}
		}
	}()
	if err := writeReply(control, message{Device: env.owner.Device, Address: env.owner.Address, MTU: env.mtu}, env.file); err != nil {
		return nil
	}
	data := make([]byte, 8192)
	for {
		size, err := control.Read(data)
		if err != nil || size == 0 {
			return nil
		}
		var request message
		if err := json.Unmarshal(data[:size], &request); err != nil {
			return err
		}
		reply := message{ID: request.ID}
		if request.Stop {
			if err := env.cleanup(); err != nil {
				reply.Error = err.Error()
			} else {
				cleaned = true
			}
			writeReply(control, reply, nil)
			return nil
		}
		if err := env.prepareDestination(request.Destination); err != nil {
			reply.Error = err.Error()
		}
		if err := writeReply(control, reply, nil); err != nil {
			return nil
		}
	}
}

func allocateAddress(r *registry) (net.IP, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, pool := range [][2]byte{{198, 18}, {198, 19}, {10, 203}, {172, 31}} {
		for attempt := 0; attempt < 1024; attempt++ {
			var random [2]byte
			if _, err := rand.Read(random[:]); err != nil {
				return nil, err
			}
			host := net.IPv4(pool[0], pool[1], random[0], random[1]&252|1).To4()
			subnet := &net.IPNet{IP: host.Mask(net.CIDRMask(30, 32)), Mask: net.CIDRMask(30, 32)}
			conflict := false
			for _, route := range routes {
				if route.Dst == nil {
					continue
				}
				bits, _ := route.Dst.Mask.Size()
				if bits != 0 && (route.Dst.Contains(host) || subnet.Contains(route.Dst.IP)) {
					conflict = true
					break
				}
			}
			for _, address := range addresses {
				if subnet.Contains(address.IP) || address.IPNet.Contains(host) {
					conflict = true
					break
				}
			}
			for _, o := range r.Owners {
				if subnet.Contains(net.ParseIP(o.Address)) {
					conflict = true
					break
				}
			}
			if !conflict {
				return host, nil
			}
		}
	}
	return nil, fmt.Errorf("no unused /30 subnet found for automatic TCP networking")
}

func openTemporaryTUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	req, err := unix.NewIfreq(name)
	if err == nil {
		req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, req)
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Deliberately do not set TUNSETPERSIST: the kernel deletes this device
	// and its connected route when the last descriptor is closed.
	return os.NewFile(uintptr(fd), name), nil
}

func prepareEnvironment() (*environment, error) {
	// Mixing nftables exceptions with active legacy iptables forwarding chains
	// cannot reliably override a legacy DROP. Fail explicitly instead of silently
	// creating a network which will never complete its TCP handshakes.
	if tables, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil && strings.TrimSpace(string(tables)) != "" {
		return nil, fmt.Errorf("automatic tcpFingerprint networking requires nftables/iptables-nft; legacy iptables tables are active (manual tcpFingerprintSettings remains available)")
	}
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(random[:])
	e := &environment{token: token, mtu: 1500, interfaces: make(map[int]string)}
	err := withRegistry(func(r *registry, path string) error {
		host, err := allocateAddress(r)
		if err != nil {
			return err
		}
		guest := append(net.IP(nil), host...)
		guest[3]++
		e.owner = owner{PID: os.Getpid(), Start: processStart(os.Getpid()), Device: "xfp" + token, Address: guest.String(), Table: "xray_fp_" + token}
		r.Owners[token] = e.owner
		if err := saveRegistry(path, r); err != nil {
			return err
		}
		e.file, err = openTemporaryTUN(e.owner.Device)
		if err != nil {
			return err
		}
		link, err := netlink.LinkByName(e.owner.Device)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetAlias(link, e.owner.Table); err != nil {
			return err
		}
		if err := netlink.LinkSetMTU(link, int(e.mtu)); err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: &net.IPNet{IP: host, Mask: net.CIDRMask(30, 32)}}); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		// Forward packets entering our own interface. Shared real interfaces
		// are enabled lazily when a destination is actually dialed.
		if err := os.WriteFile(forwardingPath(e.owner.Device), []byte("1\n"), 0600); err != nil {
			return err
		}
		return installRules(e.owner)
	})
	if err != nil {
		cleanupErr := e.cleanup()
		if e.file != nil {
			e.file.Close()
		}
		return nil, errors.Join(err, cleanupErr)
	}
	return e, nil
}

func (e *environment) prepareDestination(address string) error {
	ip := net.ParseIP(address).To4()
	if ip == nil {
		return fmt.Errorf("expected an IPv4 destination")
	}
	// Query only; this does not transmit packets or rewrite routes.
	routes, err := netlink.RouteGetWithOptions(ip, &netlink.RouteGetOptions{Iif: e.owner.Device, SrcAddr: net.ParseIP(e.owner.Address)})
	if err != nil {
		return fmt.Errorf("route to %s: %w", address, err)
	}
	for _, route := range routes {
		if route.Type == unix.RTN_LOCAL {
			return nil
		}
		if route.Type != unix.RTN_UNICAST {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return err
		}
		if e.interfaces[route.LinkIndex] == link.Attrs().Name {
			return nil
		}
		if err := withRegistry(func(r *registry, path string) error { return acquireForwarding(r, path, e.token, link) }); err != nil {
			return err
		}
		e.interfaces[route.LinkIndex] = link.Attrs().Name
		return nil
	}
	return fmt.Errorf("no usable IPv4 route to %s", address)
}

func (e *environment) cleanup() error {
	return withRegistry(func(r *registry, _ string) error { return cleanupOwner(r, e.token) })
}

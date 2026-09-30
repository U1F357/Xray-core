package wireguard

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	wgconn "golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Exercise the real WireGuard encrypted UDP transport and the existing Xray
// userspace netTun adapter, not freedom's new network adapter. No root required.
func TestFingerprintWireGuardNativeTunnel(t *testing.T) {
	type peer struct {
		dev    *device.Device
		net    *Net
		stack  *stack.Stack
		public string
		port   string
	}
	makePeer := func(address string) *peer {
		tun, n, s, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1420, true)
		if err != nil {
			t.Fatal(err)
		}
		d := device.NewDevice(tun, wgconn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "test"))
		t.Cleanup(func() { d.Close(); s.Wait() })
		var profile tcpip.TCPFingerprintProfile
		if e := s.TransportProtocolOption(tcp.ProtocolNumber, &profile); e != nil || profile != tcpip.TCPFingerprintNative {
			t.Fatalf("non-native stack: %v %v", profile, e)
		}
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.IpcSet("private_key=" + hex.EncodeToString(key.Bytes()) + "\nlisten_port=0\n"); err != nil {
			t.Fatal(err)
		}
		if err = d.Up(); err != nil {
			t.Fatal(err)
		}
		conf, err := d.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		port := ""
		for _, line := range strings.Split(conf, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				port = strings.TrimPrefix(line, "listen_port=")
			}
		}
		if port == "" || port == "0" {
			t.Fatal("no WireGuard UDP port")
		}
		return &peer{d, n, s, hex.EncodeToString(key.PublicKey().Bytes()), port}
	}
	left, right := makePeer("10.55.0.1"), makePeer("10.55.0.2")
	for _, pair := range []struct {
		from, to *peer
		ip       string
	}{{left, right, "10.55.0.2"}, {right, left, "10.55.0.1"}} {
		conf := fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%s\nallowed_ip=%s/32\n", pair.to.public, pair.to.port, pair.ip)
		if err := pair.from.dev.IpcSet(conf); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := gonet.ListenTCP(right.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 55, 0, 2}), Port: 23456}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("native TCP over encrypted WireGuard\n"), 4096)
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		b := make([]byte, len(payload))
		_, e = io.ReadFull(c, b)
		if e == nil && !bytes.Equal(b, payload) {
			e = fmt.Errorf("payload mismatch")
		}
		if e == nil {
			_, e = c.Write(b)
		}
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := left.net.DialContext(ctx, "tcp", "10.55.0.2:23456")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("TCP response mismatch")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	udp, err := gonet.DialUDP(right.stack, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 55, 0, 2}), Port: 23457}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(10 * time.Second))
	go func() {
		b := make([]byte, 1024)
		n, addr, e := udp.ReadFrom(b)
		if e == nil {
			_, e = udp.WriteTo(b[:n], addr)
		}
		done <- e
	}()
	uc, err := left.net.DialContext(ctx, "udp", "10.55.0.2:23457")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = uc.Write([]byte("native UDP")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "native UDP" {
		t.Fatalf("UDP response: %q %v", buf[:n], err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

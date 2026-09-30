//go:build linux

package freedom

import (
	"context"
	"errors"
	stdnet "net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// The local integration harness supplies an exclusive, preconfigured TUN.
func TestFingerprintLifecycle(t *testing.T) {
	tun := os.Getenv("XRAY_FP_TEST_TUN")
	if tun == "" {
		t.Skip("run with the fingerprint integration harness")
	}
	listener, err := stdnet.Listen("tcp4", stdnet.JoinHostPort(os.Getenv("XRAY_FP_TEST_HOST"), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	destination := net.DestinationFromAddr(listener.Addr())
	baseline := 0
	for i := 0; i < 4; i++ {
		d, err := newFingerprintDialer(&Config{TcpFingerprint: "windows", TcpFingerprintSettings: &TCPFingerprintSettings{Tun: tun, Address: os.Getenv("XRAY_FP_TEST_ADDRESS")}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := d.Dial(ctx, destination)
		cancel()
		if err != nil {
			d.Close()
			t.Fatal(err)
		}
		peer, err := listener.Accept()
		if err != nil {
			conn.Close()
			d.Close()
			t.Fatal(err)
		}
		readDone := make(chan error, 1)
		go func() { var b [1]byte; _, err := conn.Read(b[:]); readDone <- err }()
		closeDone := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			for j := 0; j < 2; j++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := d.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			close(closeDone)
		}()
		select {
		case <-closeDone:
		case <-time.After(3 * time.Second):
			t.Fatal("Close hung")
		}
		select {
		case err := <-readDone:
			if err == nil {
				t.Error("active read succeeded after Close")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("active read was not interrupted")
		}
		conn.Close()
		peer.Close()
		if _, err := d.Dial(context.Background(), destination); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Dial after Close = %v", err)
		}
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			baseline = len(fds)
		} else if len(fds) > baseline {
			t.Fatalf("file descriptor leak: before %d, now %d", baseline, len(fds))
		}
	}
}

func TestFingerprintNativeDefault(t *testing.T) {
	s := stack.New(stack.Options{TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer s.Close()
	var p tcpip.TCPFingerprintProfile
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &p); err != nil || p != tcpip.TCPFingerprintNative {
		t.Fatalf("default profile=%v error=%v", p, err)
	}
}

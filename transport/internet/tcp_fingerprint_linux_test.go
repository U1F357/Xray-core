//go:build linux

package internet

import (
	"context"
	"net"
	"syscall"
	"testing"
)

func TestTCPFingerprintSavedSYN(t *testing.T) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error { return c.Control(enableSavedSYN) }}
	lc.SetMultipathTCP(false)
	listener, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if got := ReadTCPFingerprint(server); got != "linux" {
		t.Fatalf("local SYN classification: %q", got)
	}
	if got := ReadTCPFingerprint(server); got != "" {
		t.Fatal("SYN must be consumed once")
	}
}

// Capture must be opt-in; unrelated listeners keep Go's original MPTCP policy.
func TestTCPFingerprintListenerIsolation(t *testing.T) {
	for _, capture := range []bool{false, true, false} {
		ctx := context.Background()
		if capture {
			ctx = ContextWithActiveTCPFingerprintCapture(ContextWithTCPFingerprintCapture(ctx, true))
		}
		dl := DefaultListener{}
		l, err := dl.Listen(ctx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		client, err := net.Dial("tcp4", l.Addr().String())
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		server, err := l.Accept()
		if err != nil {
			client.Close()
			l.Close()
			t.Fatal(err)
		}
		got := ReadTCPFingerprint(server)
		server.Close()
		client.Close()
		l.Close()
		if capture && got != "linux" {
			t.Fatalf("enabled capture: %q", got)
		}
		if !capture && got != "" {
			t.Fatalf("disabled capture retained SYN: %q", got)
		}
	}
}

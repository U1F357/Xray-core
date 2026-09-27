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

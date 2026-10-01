//go:build linux

package internet

import (
	"net"
	"testing"
)

func TestTCPInitialRTTAtAccept(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := ReadInitialTCPRTT(server); got == 0 {
		t.Fatal("no RTT on established native TCP")
	}
	server.Close()
	if got := ReadInitialTCPRTT(server); got != 0 {
		t.Fatal("closed socket returned RTT", got)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := ReadInitialTCPRTT(a); got != 0 {
		t.Fatal("non TCP accepted")
	}
}

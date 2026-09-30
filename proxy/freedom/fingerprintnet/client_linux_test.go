//go:build linux

package fingerprintnet

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCanceledReplyCannotSatisfyNextRequest(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	client, err := unixConn(os.NewFile(uintptr(fds[0]), "client"))
	if err != nil {
		unix.Close(fds[1])
		t.Fatal(err)
	}
	defer client.Close()
	server, err := unixConn(os.NewFile(uintptr(fds[1]), "server"))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	n := &Network{control: client}
	firstReceived := make(chan struct{})
	releaseFirst := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		b := make([]byte, 1024)
		for i := 0; i < 2; i++ {
			size, err := server.Read(b)
			if err != nil {
				done <- err
				return
			}
			var request message
			if err := json.Unmarshal(b[:size], &request); err != nil {
				done <- err
				return
			}
			if i == 0 {
				close(firstReceived)
				<-releaseFirst
			}
			reply := message{ID: request.ID, MTU: uint32(1500 - i*220)}
			if i == 0 {
				reply.Error = "stale error must not leak to next request"
			}
			if err := writeReply(server, reply, nil); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- n.PrepareDestination(ctx, "192.0.2.1") }()
	<-firstReceived
	cancel()
	select {
	case err := <-first:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt control read")
	}
	close(releaseFirst)
	if mtu, err := n.PrepareDestinationMTU(context.Background(), "192.0.2.2"); err != nil || mtu != 1280 {
		t.Fatalf("MTU reply = %d, error = %v", mtu, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProcessIdentity(t *testing.T) {
	if start := processStart(os.Getpid()); start == "" || start != processStart(os.Getpid()) {
		t.Fatalf("unstable process identity %q", start)
	}
	if start := processStart(-1); start != "" {
		t.Fatalf("invalid PID has identity %q", start)
	}
}

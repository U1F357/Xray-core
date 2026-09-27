//go:build linux

// Package fingerprintnet owns automatic Linux networking for a userspace stack.
// The helper is the same executable, with an inherited private control socket.
package fingerprintnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const helperArgument = "__xray_fingerprint_network"

type message struct {
	ID          uint64
	Device      string
	Address     string
	MTU         uint32
	Destination string
	Stop        bool
	Error       string
}

// Network holds a nonpersistent TUN and a lease on its host-side configuration.
type Network struct {
	File      *os.File
	Device    string
	Address   string
	MTU       uint32
	control   *net.UnixConn
	command   *exec.Cmd
	mu        sync.Mutex
	closed    bool
	requestID uint64
}

func unixConn(file *os.File) (*net.UnixConn, error) {
	c, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("expected UNIX control socket")
	}
	return u, nil
}

// Prepare creates the network before the userspace TCP stack starts.
func Prepare() (*Network, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("automatic tcpFingerprint networking requires Linux root")
	}
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	control, err := unixConn(os.NewFile(uintptr(fds[0]), "fingerprint-parent"))
	if err != nil {
		unix.Close(fds[1])
		return nil, err
	}
	child := os.NewFile(uintptr(fds[1]), "fingerprint-child")
	cmd := exec.Command(path, helperArgument)
	cmd.ExtraFiles = []*os.File{child}
	cmd.Stderr = os.Stderr
	// A signal to Xray's process group must not kill its cleanup helper.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		control.Close()
		child.Close()
		return nil, err
	}
	child.Close()
	n := &Network{control: control, command: cmd}
	control.SetReadDeadline(time.Now().Add(20 * time.Second))
	data, oob := make([]byte, 8192), make([]byte, unix.CmsgSpace(4))
	size, rightsSize, flags, _, err := control.ReadMsgUnix(data, oob)
	var received []int
	if rightsSize > 0 {
		messages, parseErr := unix.ParseSocketControlMessage(oob[:rightsSize])
		if parseErr != nil {
			err = parseErr
		}
		for _, m := range messages {
			rights, e := unix.ParseUnixRights(&m)
			if e != nil {
				err = e
			} else {
				received = append(received, rights...)
			}
		}
	}
	var reply message
	if err == nil && flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		err = fmt.Errorf("truncated helper response")
	}
	if err == nil {
		err = json.Unmarshal(data[:size], &reply)
	}
	if err == nil && reply.Error != "" {
		err = errors.New(reply.Error)
	}
	if err == nil && len(received) != 1 {
		err = fmt.Errorf("helper did not supply one TUN descriptor")
	}
	if err != nil {
		for _, fd := range received {
			unix.Close(fd)
		}
		control.Close()
		waitHelper(cmd)
		return nil, fmt.Errorf("automatic tcpFingerprint network: %w", err)
	}
	unix.CloseOnExec(received[0])
	n.File = os.NewFile(uintptr(received[0]), reply.Device)
	n.Device, n.Address, n.MTU = reply.Device, reply.Address, reply.MTU
	control.SetDeadline(time.Time{})
	return n, nil
}

// PrepareDestination enables forwarding on the interface selected by the host
// route for this destination. No default route or global ip_forward is changed.
func (n *Network) PrepareDestination(ctx context.Context, address string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	n.control.SetDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { n.control.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		n.control.SetDeadline(time.Time{})
	}()
	return n.exchange(message{Destination: address})
}

func (n *Network) exchange(request message) error {
	c := n.control
	n.requestID++
	request.ID = n.requestID
	data, _ := json.Marshal(request)
	if _, err := c.Write(data); err != nil {
		return err
	}
	buffer := make([]byte, 8192)
	for {
		size, err := c.Read(buffer)
		if err != nil {
			return err
		}
		var reply message
		if err := json.Unmarshal(buffer[:size], &reply); err != nil {
			return err
		}
		// A canceled request may leave its reply queued on the socket.
		if reply.ID != request.ID {
			continue
		}
		if reply.Error != "" {
			return errors.New(reply.Error)
		}
		return nil
	}
}

func waitHelper(cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		cmd.Process.Kill()
		return errors.Join(fmt.Errorf("network helper did not stop; journaled cleanup will be retried at next startup"), <-done)
	}
}

// Close waits until the helper has removed its rules and released forwarding
// leases. The caller must first close File and stop userspace packet processing.
func (n *Network) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	n.control.SetDeadline(time.Now().Add(10 * time.Second))
	err := n.exchange(message{Stop: true})
	n.control.Close()
	waitErr := waitHelper(n.command)
	return errors.Join(err, waitErr)
}

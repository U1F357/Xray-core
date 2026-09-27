package freedom

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
)

func TestFingerprintValidation(t *testing.T) {
	for _, profile := range []string{"windows", "macos", "linux"} {
		c := &Config{TcpFingerprint: profile, TcpFingerprintSettings: &TCPFingerprintSettings{Tun: "xrfp0", Address: "10.203.0.2"}}
		if err := ValidateTCPFingerprint(c); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*Config{
		{TcpFingerprint: "unknown"},
		{TcpFingerprint: "windows", TcpFingerprintSettings: &TCPFingerprintSettings{}},
		{TcpFingerprintSettings: &TCPFingerprintSettings{Tun: "xrfp0", Address: "10.203.0.2"}},
		{TcpFingerprint: "windows", TcpFingerprintSettings: &TCPFingerprintSettings{Tun: "xrfp0", Address: "::1"}},
		{TcpFingerprint: "windows", TcpFingerprintSettings: &TCPFingerprintSettings{Tun: "xrfp0", Address: "0.0.0.0"}},
		{TcpFingerprint: "windows", TcpFingerprintSettings: &TCPFingerprintSettings{Tun: "bad/name", Address: "10.203.0.2"}},
	} {
		if err := ValidateTCPFingerprint(c); err == nil {
			t.Fatalf("accepted invalid config: %v", c)
		}
	}
	if err := ValidateTCPFingerprint(&Config{}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTCPFingerprint(&Config{TcpFingerprint: "windows"}); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintStreamRestrictions(t *testing.T) {
	for _, s := range []*internet.MemoryStreamConfig{
		{ProtocolName: "websocket"},
		{ProtocolName: "tcp", SecurityType: "tls"},
		{SocketSettings: &internet.SocketConfig{DialerProxy: "other"}},
		{SocketSettings: &internet.SocketConfig{Mark: 123}},
	} {
		if err := validateFingerprintStream(s); err == nil {
			t.Fatalf("accepted unsupported stream: %+v", s)
		}
	}
	if err := validateFingerprintStream(&internet.MemoryStreamConfig{ProtocolName: "tcp", SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_FORCE_IP4}}); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintAddress(t *testing.T) {
	h := &Handler{config: &Config{}}
	if _, err := h.fingerprintAddress(context.Background(), net.ParseAddress("2001:db8::1")); err == nil {
		t.Fatal("accepted IPv6")
	}
	addr, err := h.fingerprintAddress(context.Background(), net.ParseAddress("192.0.2.1"))
	if err != nil || addr.String() != "192.0.2.1" {
		t.Fatalf("address = %v, error = %v", addr, err)
	}
}

type fakeFingerprintDialer struct {
	calls  atomic.Int32
	closed atomic.Int32
}

func (d *fakeFingerprintDialer) Dial(context.Context, net.Destination) (net.Conn, error) {
	d.calls.Add(1)
	return nil, nil
}
func (d *fakeFingerprintDialer) Close() error { d.closed.Add(1); return nil }
func TestFingerprintAutoSelection(t *testing.T) {
	profiles := map[string]*fakeFingerprintDialer{}
	d, err := newSelectingFingerprintDialer(&Config{TcpFingerprint: "auto", TcpFingerprintFallback: "macos"}, func(c *Config) (fingerprintDialer, error) {
		s := new(fakeFingerprintDialer)
		profiles[c.TcpFingerprint] = s
		return s, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		for _, p := range []string{"windows", "macos", "linux", "unknown", ""} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := session.ContextWithInbound(context.Background(), &session.Inbound{TCPFingerprint: p})
				d.Dial(ctx, net.Destination{})
			}()
		}
	}
	wg.Wait()
	for p, s := range profiles {
		want := int32(30)
		if p == "macos" {
			want = 90
		}
		if s.calls.Load() != want {
			t.Fatalf("%s calls: %d", p, s.calls.Load())
		}
	}
	d.Close()
	d.Close()
	for _, s := range profiles {
		if s.closed.Load() != 1 {
			t.Fatal("close was not idempotent")
		}
	}
}
func TestFingerprintAutoRollback(t *testing.T) {
	first := new(fakeFingerprintDialer)
	calls := 0
	_, err := newSelectingFingerprintDialer(&Config{TcpFingerprint: "auto"}, func(c *Config) (fingerprintDialer, error) {
		calls++
		if calls == 2 {
			return nil, fmt.Errorf("setup failed")
		}
		return first, nil
	})
	if err == nil || first.closed.Load() != 1 {
		t.Fatal("failed initialization did not roll back")
	}
	for _, c := range []*Config{{TcpFingerprint: "auto", TcpFingerprintFallback: "unknown"}, {TcpFingerprint: "linux", TcpFingerprintFallback: "linux"}, {TcpFingerprint: "auto", TcpFingerprintSettings: &TCPFingerprintSettings{Tun: "test", Address: "10.0.0.2"}}} {
		if ValidateTCPFingerprint(c) == nil {
			t.Fatalf("accepted %v", c)
		}
	}
}

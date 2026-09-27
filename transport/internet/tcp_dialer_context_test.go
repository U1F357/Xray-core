package internet

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestTCPDialerOverride(t *testing.T) {
	sentinel := errors.New("custom TCP dial")
	calls := 0
	ctx := ContextWithTCPDialer(context.Background(), func(_ context.Context, dest net.Destination) (net.Conn, error) {
		calls++
		if dest.Network != net.Network_TCP {
			t.Fatal("UDP reached TCP override")
		}
		return nil, sentinel
	})
	if _, err := Dial(ctx, net.TCPDestination(net.LocalHostIP, 443), nil); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	_, _ = Dial(ctx, net.UDPDestination(net.LocalHostIP, 53), nil)
	if calls != 1 {
		t.Fatalf("TCP override called %d times", calls)
	}
}

package internet

import (
	"context"

	"github.com/xtls/xray-core/common/net"
)

type tcpDialerContextKey struct{}

// TCPDialFunc establishes a TCP connection using an outbound-owned network stack.
type TCPDialFunc func(context.Context, net.Destination) (net.Conn, error)

// ContextWithTCPDialer preserves outbound accounting while replacing the TCP
// transport. Callers must validate incompatible stream settings.
func ContextWithTCPDialer(ctx context.Context, dial TCPDialFunc) context.Context {
	return context.WithValue(ctx, tcpDialerContextKey{}, dial)
}

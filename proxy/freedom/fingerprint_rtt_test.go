package freedom

import (
	"context"
	"github.com/xtls/xray-core/common/session"
	"testing"
	"time"
)

func TestTCPAutoRTTSelection(t *testing.T) {
	c := &TCPAutoRTT{FallbackMs: 100, MinMs: 5, MaxMs: 300}
	for _, tc := range []struct {
		us     uint32
		source string
		want   int64
		origin string
	}{
		{0, "", 100, "fallback"}, {0, "vless", 100, "fallback"}, {100001, "tcp_info", 101, "tcp_info"},
		{1, "tcp_info", 5, "tcp_info"}, {999999, "vless", 300, "vless"}, {^uint32(0), "vless", 300, "vless"},
		{100000, "", 100, "fallback"},
	} {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{TCPRTTUs: tc.us, TCPRTTSource: tc.source})
		d, source, _ := selectTCPRTT(ctx, c)
		if d.Milliseconds() != tc.want || source != tc.origin {
			t.Fatalf("%+v: %v %s", tc, d, source)
		}
	}
}
func TestTCPAutoRTTFlowIsolation(t *testing.T) {
	d := newACKDelayer(context.Background(), &TCPAckDelay{MinMs: 90, MaxMs: 90}, func([]byte) {}, nil)
	a, b := 10*time.Millisecond, 200*time.Millisecond
	first, second := &ackDelayFlow{fixedDelay: &a}, &ackDelayFlow{fixedDelay: &b}
	for range 100 {
		if d.sampleDelay(first) != a || d.sampleDelay(second) != b || d.sampleDelay(&ackDelayFlow{}) != 90*time.Millisecond {
			t.Fatal("cross-flow delay contamination")
		}
	}
}

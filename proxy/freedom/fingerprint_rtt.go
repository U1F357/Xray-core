package freedom

import (
	"context"
	"github.com/xtls/xray-core/common/session"
	"time"
)

// A connection uses one immutable initial estimate, never a global moving value.
// This is the extra ACK age, so target RTT is exit-path RTT plus this value.
func selectTCPRTT(ctx context.Context, c *TCPAutoRTT) (time.Duration, string, uint32) {
	us, source := uint32(0), "fallback"
	if in := session.InboundFromContext(ctx); in != nil && in.TCPRTTSource != "" {
		us = in.TCPRTTUs
		if us != 0 {
			source = in.TCPRTTSource
		}
	}
	ms := (uint64(us) + 999) / 1000
	if us == 0 {
		ms = uint64(c.FallbackMs)
	}
	if ms < uint64(c.MinMs) {
		ms = uint64(c.MinMs)
	}
	if ms > uint64(c.MaxMs) {
		ms = uint64(c.MaxMs)
	}
	return time.Duration(ms) * time.Millisecond, source, us
}

func (d *ackDelayer) sampleDelay(f *ackDelayFlow) time.Duration {
	if f.fixedDelay != nil {
		return *f.fixedDelay
	}
	return d.sample()
}
func (d *ackDelayer) maxDelay(f *ackDelayFlow) time.Duration {
	if f.fixedDelay != nil {
		return *f.fixedDelay
	}
	return time.Duration(d.cfg.MaxMs) * time.Millisecond
}

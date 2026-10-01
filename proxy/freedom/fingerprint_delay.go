package freedom

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

type synACKFlow struct {
	local, remote         tcpip.Address
	localPort, remotePort uint16
}

type delayedSYNACK struct {
	ctx      context.Context
	wake     chan struct{}
	done     chan struct{}
	delay    time.Duration
	deadline time.Time
	packets  [][]byte
	bytes    int
	released bool
}

// One bounded queue per active dial. Nothing waits on a timer in the TUN reader.
// Entries live only until Connect completes/cancels, so established connections
// and subsequently reused tuples cannot inherit an earlier delay.
type synACKDelayer struct {
	mu      sync.Mutex
	pending map[synACKFlow]*delayedSYNACK
	inject  func([]byte)
}

func randomHandshakeDelay(r *TCPHandshakeDelay) time.Duration {
	return time.Duration(uint64(r.MinMs)+rand.Uint64N(uint64(r.MaxMs-r.MinMs)+1)) * time.Millisecond
}

// Caller holds mu across Connect and registration to avoid an early reply race.
func (d *synACKDelayer) registerLocked(ctx context.Context, key synACKFlow, delay time.Duration) func() {
	ctx, cancel := context.WithCancel(ctx)
	e := &delayedSYNACK{ctx: ctx, wake: make(chan struct{}, 1), done: make(chan struct{}), delay: delay}
	d.pending[key] = e
	go d.deliver(e)
	return func() {
		cancel()
		d.mu.Lock()
		if d.pending[key] == e {
			delete(d.pending, key)
		}
		d.mu.Unlock()
		<-e.done
	}
}

func (d *synACKDelayer) deliver(e *delayedSYNACK) {
	defer close(e.done)
	select {
	case <-e.ctx.Done():
		return
	case <-e.wake:
	}
	d.mu.Lock()
	deadline := e.deadline
	d.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-e.ctx.Done():
		return
	case <-timer.C:
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if e.ctx.Err() != nil {
		return
	}
	// Delivery is short and synchronous. Serializing it with enqueue preserves
	// order if another SYN-ACK arrives precisely at the deadline.
	for _, packet := range e.packets {
		d.inject(packet)
	}
	e.packets = nil
	e.bytes = 0
	e.released = true
}

func (d *synACKDelayer) enqueue(packet []byte) bool {
	key, ok := synACKTuple(packet)
	if !ok {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.pending[key]
	if e == nil || e.released || e.delay == 0 {
		return false
	}
	if e.ctx.Err() != nil {
		return true
	}
	if e.deadline.IsZero() {
		e.deadline = time.Now().Add(e.delay)
		e.wake <- struct{}{}
	}
	// Bound duplicate/retransmission memory. TCP can retry dropped excess packets.
	if len(e.packets) < 8 && e.bytes+len(packet) <= 65535 {
		e.packets = append(e.packets, append([]byte(nil), packet...))
		e.bytes += len(packet)
	}
	return true
}

// Parse complete, unfragmented TCP packets, including IPv4 options and
// IPv6 hop-by-hop/routing/destination/AH headers. Other traffic goes straight to
// the stack, which remains responsible for checksums and TCP validity.
func tcpDelayTuple(p []byte) (synACKFlow, []byte) {
	var key synACKFlow
	if len(p) < 20 {
		return key, nil
	}
	offset := 0
	switch p[0] >> 4 {
	case 4:
		offset = int(p[0]&15) * 4
		total := int(binary.BigEndian.Uint16(p[2:4]))
		if offset < 20 || total < offset+20 || total > len(p) || p[9] != 6 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return key, nil
		}
		p = p[:total]
		key.remote = tcpip.AddrFromSlice(p[12:16])
		key.local = tcpip.AddrFromSlice(p[16:20])
	case 6:
		if len(p) < 40 {
			return key, nil
		}
		total := 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if total > len(p) {
			return key, nil
		}
		p = p[:total]
		key.remote = tcpip.AddrFromSlice(p[8:24])
		key.local = tcpip.AddrFromSlice(p[24:40])
		offset = 40
		next := p[6]
		for next != 6 {
			if offset+2 > len(p) {
				return key, nil
			}
			kind := next
			next = p[offset]
			switch kind {
			case 0, 43, 60:
				offset += (int(p[offset+1]) + 1) * 8
			case 51:
				offset += (int(p[offset+1]) + 2) * 4
			default:
				return key, nil
			}
		}
	default:
		return key, nil
	}
	if offset+20 > len(p) {
		return key, nil
	}
	h := p[offset:]
	size := int(h[12]>>4) * 4
	if size < 20 || size > len(h) {
		return key, nil
	}
	key.remotePort = binary.BigEndian.Uint16(h[:2])
	key.localPort = binary.BigEndian.Uint16(h[2:4])
	return key, h
}

func synACKTuple(p []byte) (synACKFlow, bool) {
	key, h := tcpDelayTuple(p)
	return key, h != nil && h[13]&0x17 == 0x12
}

package freedom

import (
	"container/heap"
	"context"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"time"
)

const ackDelayFlowBytes = 4 << 20
const ackDelayTotalBytes = 32 << 20
const ackDelayTotalPackets = 16384
const ackDelayMaxFlows = 16384

type ackDelayFlow struct {
	fixedDelay        *time.Duration
	probeUntil        time.Time
	probeACK          int64
	receiptLimited    bool
	localClosed       bool
	isn               uint32
	end, last, expiry time.Time
	bytes             int
	peerKnown         bool
	confirmed         int64
	receipts          []ackReceipt
	overflowUntil     time.Time
}
type ackDelayPacket struct {
	flow   *ackDelayFlow
	key    synACKFlow
	at     time.Time
	serial uint64
	data   []byte
}
type ackDelayHeap []ackDelayPacket

func (h ackDelayHeap) Len() int { return len(h) }
func (h ackDelayHeap) Less(i, j int) bool {
	if h[i].at.Equal(h[j].at) {
		return h[i].serial < h[j].serial
	}
	return h[i].at.Before(h[j].at)
}
func (h ackDelayHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *ackDelayHeap) Push(x any)   { *h = append(*h, x.(ackDelayPacket)) }
func (h *ackDelayHeap) Pop() any {
	a := *h
	n := len(a) - 1
	x := a[n]
	a[n] = ackDelayPacket{}
	*h = a[:n]
	return x
}

// A single timer serves all connections; neither packet pump waits on a timer.
// All sends pass through mu so immediate packets cannot overtake queued packets
// from the same connection at a deadline boundary.
type ackDelayer struct {
	mu       sync.Mutex
	ctx      context.Context
	cfg      TCPAckDelay
	flows    map[synACKFlow]*ackDelayFlow
	pending  map[synACKFlow]*time.Duration
	queue    ackDelayHeap
	bytes    int
	serial   uint64
	wake     chan struct{}
	send     func([]byte)
	sample   func() time.Duration
	log      func(string)
	drops    uint64
	receipts int
}

func newACKDelayer(ctx context.Context, c *TCPAckDelay, send func([]byte), log func(string)) *ackDelayer {
	cfg := TCPAckDelay{MinMs: c.MinMs, MaxMs: c.MaxMs, WindowMs: c.WindowMs, Continuous: c.Continuous, AutoRtt: c.AutoRtt}
	if cfg.WindowMs == 0 && !cfg.Continuous {
		cfg.WindowMs = 10000
	}
	d := &ackDelayer{ctx: ctx, cfg: cfg, flows: make(map[synACKFlow]*ackDelayFlow), pending: make(map[synACKFlow]*time.Duration), wake: make(chan struct{}, 1), send: send, log: log}
	d.sample = func() time.Duration {
		return time.Duration(uint64(cfg.MinMs)+rand.Uint64N(uint64(cfg.MaxMs-cfg.MinMs)+1)) * time.Millisecond
	}
	return d
}

func (d *ackDelayer) signal() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}
func (d *ackDelayer) drop() {
	d.drops++
	// Avoid a log storm while retaining a visible indication of queue pressure.
	if d.log != nil && (d.drops == 1 || d.drops%1024 == 0) {
		d.log("TCP ACK delay queue full: dropping packet; TCP retransmission required")
	}
}

func (d *ackDelayer) submit(p []byte) {
	key, h := tcpDelayTuple(p)
	// The shared parser describes incoming packets. Reverse it for egress.
	key = synACKFlow{local: key.remote, remote: key.local, localPort: key.remotePort, remotePort: key.localPort}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return
	}
	if h == nil {
		d.send(p)
		return
	}
	now := time.Now()
	flags := h[13]
	f := d.flows[key]
	if flags&4 != 0 { // Reset terminates the connection, including pending data.
		if f != nil {
			d.forget(key, f)
			d.purge(key, f)
		}
		d.send(p)
		d.signal()
		return
	}
	if flags&0x12 == 2 {
		isn := binary.BigEndian.Uint32(h[4:8])
		if f == nil || f.isn != isn {
			if f != nil {
				d.forget(key, f)
				d.purge(key, f)
			}
			if len(d.flows) >= ackDelayMaxFlows {
				d.drop()
				return
			}
			// A SYN that never completes cannot leave permanent state behind.
			d.flows[key] = &ackDelayFlow{fixedDelay: d.pending[key], isn: isn, expiry: now.Add(30 * time.Second)}
		}
		d.send(p)
		d.signal()
		return
	}
	if f == nil {
		d.send(p)
		return
	}
	due := now
	if flags&0x10 != 0 {
		if f.end.IsZero() {
			f.end = now.Add(time.Duration(d.cfg.WindowMs) * time.Millisecond)
			f.expiry = f.end.Add(d.maxDelay(f))
		}
		if d.cfg.Continuous || now.Before(f.end) {
			due = d.ackDeadline(f, h, now)
		}
	}
	// Random delays do not reorder packets or accumulate one delay per queued
	// packet. After expiry, drain the old tail before releasing new packets.
	if due.Before(f.last) {
		due = f.last
	}
	if !due.After(now) && f.bytes == 0 {
		d.confirm(f, h)
		d.send(p)
		return
	}
	if f.bytes+len(p) > ackDelayFlowBytes || d.bytes+len(p) > ackDelayTotalBytes || len(d.queue) >= ackDelayTotalPackets {
		d.drop()
		return
	}
	f.last = due
	f.bytes += len(p)
	d.bytes += len(p)
	d.serial++
	heap.Push(&d.queue, ackDelayPacket{flow: f, key: key, at: due, serial: d.serial, data: append([]byte(nil), p...)})
	d.signal()
}

// Called only for RST/tuple reuse, not for each packet.
func (d *ackDelayer) purge(key synACKFlow, f *ackDelayFlow) {
	keep := d.queue[:0]
	for _, p := range d.queue {
		if p.key == key && p.flow == f {
			d.bytes -= len(p.data)
			f.bytes -= len(p.data)
		} else {
			keep = append(keep, p)
		}
	}
	clear(d.queue[len(keep):])
	d.queue = keep
	heap.Init(&d.queue)
}

func (d *ackDelayer) run() {
	nextSweep := time.Now()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	defer func() {
		d.mu.Lock()
		clear(d.flows)
		d.queue = nil
		d.bytes = 0
		d.receipts = 0
		d.mu.Unlock()
	}()
	for {
		d.mu.Lock()
		if d.ctx.Err() != nil {
			d.mu.Unlock()
			return
		}
		now := time.Now()
		for len(d.queue) > 0 && !d.queue[0].at.After(now) {
			p := heap.Pop(&d.queue).(ackDelayPacket)
			d.bytes -= len(p.data)
			p.flow.bytes -= len(p.data)
			if d.flows[p.key] == p.flow {
				_, h := tcpDelayTuple(p.data)
				d.confirm(p.flow, h)
				d.send(p.data)
			}
			if d.ctx.Err() != nil {
				d.mu.Unlock()
				return
			}
		}
		// A one-second sweep bounds idle state without per-connection goroutines.
		if !now.Before(nextSweep) {
			for k, f := range d.flows {
				if f.bytes == 0 && !now.Before(f.expiry) && (!d.cfg.Continuous || f.end.IsZero() || f.localClosed) {
					d.forget(k, f)
				}
			}
			nextSweep = now.Add(time.Second)
		}
		wait := time.Second
		if len(d.queue) > 0 {
			if t := time.Until(d.queue[0].at); t < wait {
				wait = t
			}
		}
		d.mu.Unlock()
		timer.Reset(wait)
		select {
		case <-d.ctx.Done():
			return
		case <-d.wake:
		case <-timer.C:
		}
	}
}

package freedom

import (
	"encoding/binary"
	"time"
)

const ackReceiptPerFlow = 128
const ackReceiptTotal = 65536

// Unwrapped peer sequence intervals. Every byte keeps its first-observed
// deadline until it is acknowledged on the wire. Retransmissions do not refresh
// the clock, and ACKs carrying application data use the very same deadlines.
type ackReceipt struct {
	start, end int64
	due        time.Time
}

func (d *ackDelayer) forget(key synACKFlow, f *ackDelayFlow) {
	d.receipts -= len(f.receipts)
	f.receipts = nil
	delete(d.flows, key)
}
func (d *ackDelayer) clearReceipts(f *ackDelayFlow) {
	d.receipts -= len(f.receipts)
	f.receipts = nil
	f.overflowUntil = time.Time{}
	f.probeUntil = time.Time{}
}
func unwrapACK(seq uint32, anchor int64) int64 { return anchor + int64(int32(seq-uint32(anchor))) }

// Called on TUN ingress BEFORE injection into gVisor. Packet checksums and TCP
// validity remain the stack's responsibility; these observations only constrain
// timing and never change sequence numbers, ACKs, payload or protocol state.
func (d *ackDelayer) observe(p []byte) {
	key, h := tcpDelayTuple(p)
	if h == nil || h[13]&4 != 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return
	}
	f := d.flows[key]
	if f == nil {
		return
	}
	now := time.Now()
	if !d.cfg.Continuous && !f.end.IsZero() && !now.Before(f.end) {
		d.clearReceipts(f)
		return
	}
	if !f.peerKnown {
		if h[13]&0x12 != 0x12 || binary.BigEndian.Uint32(h[8:12]) != f.isn+1 {
			return
		}
		f.confirmed = int64(binary.BigEndian.Uint32(h[4:8]))
		f.peerKnown = true
		f.end = now.Add(time.Duration(d.cfg.WindowMs) * time.Millisecond)
		f.expiry = f.end.Add(d.maxDelay(f))
	}
	n := len(h) - int(h[12]>>4)*4
	if h[13]&2 != 0 {
		n++
	}
	if h[13]&1 != 0 {
		n++
	}
	start := unwrapACK(binary.BigEndian.Uint32(h[4:8]), f.confirmed)
	end := start + int64(n)
	// Previously acknowledged retransmissions and standard keepalive probes
	// elicit duplicate ACKs without advancing sequence space. Give that fresh
	// response a floor too, while ordinary inbound pure ACKs need no response.
	if (n > 0 && end <= f.confirmed) || (n == 0 && start == f.confirmed-1) {
		if !now.Before(f.probeUntil) || f.probeACK != f.confirmed {
			f.probeACK = f.confirmed
			f.probeUntil = now.Add(d.sampleDelay(f))
		}
		return
	}
	if n == 0 {
		return
	}
	if start < f.confirmed {
		start = f.confirmed
	}
	// Intervals outside a serial-number half-space cannot be associated safely.
	if end-f.confirmed >= 1<<31 {
		return
	}
	missing := []ackReceipt{{start: start, end: end}}
	for _, r := range f.receipts {
		next := make([]ackReceipt, 0, len(missing)+1)
		for _, m := range missing {
			if m.end <= r.start || m.start >= r.end {
				next = append(next, m)
				continue
			}
			if m.start < r.start {
				next = append(next, ackReceipt{start: m.start, end: r.start})
			}
			if m.end > r.end {
				next = append(next, ackReceipt{start: r.end, end: m.end})
			}
		}
		missing = next
		if len(missing) == 0 {
			return
		}
	}
	if len(f.receipts)+len(missing) > ackReceiptPerFlow || d.receipts+len(missing) > ackReceiptTotal {
		// Bounded conservative fallback: retain one maximum deadline, never create
		// unbounded interval state. It ends with the configured connection window.
		f.overflowUntil = now.Add(d.maxDelay(f))
		if d.log != nil && !f.receiptLimited {
			d.log("TCP ACK receipt timing reached tracking limit; using a bounded conservative deadline")
		}
		f.receiptLimited = true
		return
	}
	due := now.Add(d.sampleDelay(f))
	for _, m := range missing {
		m.due = due
		f.receipts = append(f.receipts, m)
	}
	d.receipts += len(missing)
}

// ACK delay is a minimum AGE of the acknowledged bytes, not an additional
// sleep measured from generation of this outgoing packet.
func (d *ackDelayer) ackDeadline(f *ackDelayFlow, h []byte, now time.Time) time.Time {
	due := now
	if !f.peerKnown {
		return due
	}
	ack := unwrapACK(binary.BigEndian.Uint32(h[8:12]), f.confirmed)
	sacks := ackSACKRanges(h, f.confirmed)
	for _, r := range f.receipts {
		covered := ack > r.start
		for _, s := range sacks {
			if s.start < r.end && s.end > r.start {
				covered = true
			}
		}
		if covered && r.due.After(due) {
			due = r.due
		}
	}
	if ack == f.probeACK && f.probeUntil.After(due) {
		due = f.probeUntil
	}
	if f.overflowUntil.After(due) {
		due = f.overflowUntil
	}
	return due
}

// Retire only when the ACK is actually written, never when merely queued.
func (d *ackDelayer) confirm(f *ackDelayFlow, h []byte) {
	if h == nil || h[13]&16 == 0 || !f.peerKnown {
		return
	}
	ack := unwrapACK(binary.BigEndian.Uint32(h[8:12]), f.confirmed)
	if ack <= f.confirmed {
		return
	}
	f.confirmed = ack
	before := len(f.receipts)
	keep := f.receipts[:0]
	for _, r := range f.receipts {
		if r.end <= ack {
			continue
		}
		if r.start < ack {
			r.start = ack
		}
		keep = append(keep, r)
	}
	clear(f.receipts[len(keep):])
	f.receipts = keep
	d.receipts -= before - len(keep)
}

func ackSACKRanges(h []byte, anchor int64) []ackReceipt {
	var out []ackReceipt
	limit := int(h[12]>>4) * 4
	for i := 20; i < limit; {
		kind := h[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > limit {
			break
		}
		n := int(h[i+1])
		if n < 2 || i+n > limit {
			break
		}
		if kind == 5 && n >= 10 && (n-2)%8 == 0 {
			for j := i + 2; j < i+n; j += 8 {
				start := unwrapACK(binary.BigEndian.Uint32(h[j:j+4]), anchor)
				end := unwrapACK(binary.BigEndian.Uint32(h[j+4:j+8]), anchor)
				if end > start {
					out = append(out, ackReceipt{start: start, end: end})
				}
			}
		}
		i += n
	}
	return out
}

// The handshake hold uses the same receipt deadline as outbound confirmation.
// It seeds the stack's own RTT with the wait, avoiding a fast local SYN-ACK
// sample followed by premature tail-loss probes for queued ClientHello data.
func (d *ackDelayer) synACKDeadline(p []byte, now time.Time) time.Time {
	key, h := tcpDelayTuple(p)
	if h == nil {
		return now
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f := d.flows[key]
	if f == nil {
		return now
	}
	due := now
	for _, r := range f.receipts {
		if r.due.After(due) {
			due = r.due
		}
	}
	return due
}

func (d *ackDelayer) closeFlow(key synACKFlow, expected *ackDelayFlow) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if f := d.flows[key]; f != nil && f == expected {
		f.localClosed = true
		f.expiry = time.Now().Add(30 * time.Second)
	}
	d.signal()
}

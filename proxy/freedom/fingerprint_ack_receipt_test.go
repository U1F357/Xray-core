package freedom

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func receiptLab(t *testing.T) (*ackDelayer, *ackDelayFlow, func(uint32, byte) []byte) {
	t.Helper()
	d := newACKDelayer(context.Background(), &TCPAckDelay{MinMs: 100, MaxMs: 100}, func([]byte) {}, nil)
	submitObserved(d, ackTestPacket(false, 15000, 2, 100))
	var f *ackDelayFlow
	for _, v := range d.flows {
		f = v
	}
	makeACK := func(ack uint32, flags byte) []byte {
		p := ackTestPacket(false, 15000, flags, 101)
		_, h := tcpDelayTuple(p)
		binary.BigEndian.PutUint32(h[8:12], ack)
		return p
	}
	_, h := tcpDelayTuple(makeACK(0, 16))
	d.confirm(f, h) // SYN at 0xffffffff; next seq wraps to 0.
	return d, f, makeACK
}

func observeData(d *ackDelayer, seq uint32) {
	p := reverseACKPacket(ackTestPacket(false, 15000, 0x18, seq)) // Three payload bytes.
	d.observe(p)
}

func TestTCPAckReceiptRemainingAgeAndRetransmission(t *testing.T) {
	d, f, ack := receiptLab(t)
	observeData(d, 0)
	if len(f.receipts) != 1 {
		t.Fatal(f.receipts)
	}
	due := f.receipts[0].due
	for _, flags := range []byte{16, 24} {
		_, h := tcpDelayTuple(ack(3, flags))
		now := due.Add(-30 * time.Millisecond)
		if got := d.ackDeadline(f, h, now); !got.Equal(due) {
			t.Fatal("must wait remaining 30 ms", got, due)
		}
		now = due.Add(time.Millisecond)
		if got := d.ackDeadline(f, h, now); !got.Equal(now) {
			t.Fatal("late reply delayed again", got, now)
		}
	}
	observeData(d, 0)
	if len(f.receipts) != 1 || !f.receipts[0].due.Equal(due) {
		t.Fatal("retransmission restarted timer")
	}
	// Duplicate/partial overlap preserves the old bytes and tracks only new bytes.
	observeData(d, 2)
	if len(f.receipts) != 2 || f.receipts[1].start != 1<<32+3 || f.receipts[1].end != 1<<32+5 {
		t.Fatal(f.receipts)
	}
	_, h := tcpDelayTuple(ack(2, 16))
	d.confirm(f, h)
	if f.confirmed != 1<<32+2 || f.receipts[0].start != f.confirmed {
		t.Fatal("partial ACK accounting")
	}
	_, h = tcpDelayTuple(ack(5, 16))
	d.confirm(f, h)
	observeData(d, 0)
	if len(f.receipts) != 0 || d.receipts != 0 {
		t.Fatal("old retransmission tracked again")
	}
}

func TestTCPAckReceiptOutOfOrderSACKAndBounds(t *testing.T) {
	d, f, ack := receiptLab(t)
	observeData(d, 6)
	p := ack(0, 16)
	_, h := tcpDelayTuple(p)
	now := time.Now()
	if got := d.ackDeadline(f, h, now); !got.Equal(now) {
		t.Fatal("unrelated cumulative ACK held")
	}
	p = append(p, 5, 10, 0, 0, 0, 6, 0, 0, 0, 9, 1, 1)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	_, h = tcpDelayTuple(p)
	h[12] = 8 << 4
	// Parse again after extending the TCP header.
	_, h = tcpDelayTuple(p)
	if got := d.ackDeadline(f, h, now); !got.Equal(f.receipts[0].due) {
		t.Fatal("SACK bypassed deadline")
	}
	for i := 0; i < ackReceiptPerFlow+5; i++ {
		observeData(d, uint32(20+i*4))
	}
	if len(f.receipts) > ackReceiptPerFlow || f.overflowUntil.IsZero() {
		t.Fatal("tracking bound not enforced")
	}
	f.end = time.Now().Add(-time.Second)
	observeData(d, 10000)
	if len(f.receipts) != 0 || d.receipts != 0 {
		t.Fatal("expired receipts retained")
	}
}

func TestTCPAckReceiptUnknownPeerAndCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := newACKDelayer(ctx, &TCPAckDelay{MaxMs: 100}, func([]byte) {}, nil)
	d.submit(ackTestPacket(false, 15000, 2, 100))
	p := reverseACKPacket(ackTestPacket(false, 15000, 0x12, 900))
	d.observe(p) // Invalid SYN-ACK acknowledgment cannot establish peer anchor.
	for _, f := range d.flows {
		if f.peerKnown {
			t.Fatal("invalid SYN ACK accepted")
		}
	}
	submitObserved(d, ackTestPacket(false, 15000, 2, 100))
	if d.receipts != 1 {
		t.Fatal(d.receipts)
	}
	d.submit(ackTestPacket(false, 15000, 0x14, 101))
	if d.receipts != 0 {
		t.Fatal("reset retained receipts")
	}
	cancel()
	d.run()
}

func TestTCPAckReceiptOverdueQueueCannotBeOvertaken(t *testing.T) {
	d, f, ack := receiptLab(t)
	observeData(d, 0)
	d.submit(ack(3, 16))
	// Simulate a scheduler that has not yet run despite expiry of its head.
	d.queue[0].at = time.Now().Add(-time.Second)
	f.last = d.queue[0].at
	for i := range f.receipts {
		f.receipts[i].due = f.last
	}
	d.submit(ack(3, 24))
	if len(d.queue) != 2 {
		t.Fatal("new data bypassed overdue ACK")
	}
}

func TestTCPAckReceiptContinuousLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := newACKDelayer(ctx, &TCPAckDelay{MinMs: 100, MaxMs: 100, Continuous: true}, func([]byte) {}, nil)
	submitObserved(d, ackTestPacket(false, 15000, 2, 100))
	var key synACKFlow
	var f *ackDelayFlow
	for k, v := range d.flows {
		key, f = k, v
	}
	// Simulate a long-idle established connection. Continuous state survives.
	f.end = time.Now().Add(-time.Hour)
	f.expiry = time.Now().Add(-time.Second)
	done := make(chan struct{})
	go func() { d.run(); close(done) }()
	time.Sleep(20 * time.Millisecond)
	d.mu.Lock()
	present := d.flows[key] == f
	d.mu.Unlock()
	if !present {
		t.Fatal("continuous state expired")
	}
	observeData(d, 0)
	d.mu.Lock()
	n := len(f.receipts)
	d.mu.Unlock()
	if n < 2 {
		t.Fatal("later receive not tracked")
	}
	// Late Close of a recycled tuple must not close the replacement owner.
	d.closeFlow(key, &ackDelayFlow{})
	d.mu.Lock()
	closed := f.localClosed
	d.mu.Unlock()
	if closed {
		t.Fatal("wrong owner closed new flow")
	}
	d.closeFlow(key, f)
	d.mu.Lock()
	if !f.localClosed {
		t.Fatal("owner close not recorded")
	}
	d.mu.Unlock()
	cancel()
	<-done
	if d.receipts != 0 {
		t.Fatal("receipt memory retained")
	}
}

func TestTCPAckReceiptHandshakeUsesSameDeadline(t *testing.T) {
	d := newACKDelayer(context.Background(), &TCPAckDelay{MinMs: 100, MaxMs: 100}, func([]byte) {}, nil)
	syn := ackTestPacket(false, 15000, 2, 100)
	submitObserved(d, syn)
	p := reverseACKPacket(ackTestPacket(false, 15000, 0x12, 0xffffffff))
	_, h := tcpDelayTuple(p)
	binary.BigEndian.PutUint32(h[8:12], 101)
	now := time.Now()
	deadline := d.synACKDeadline(p, now)
	if deadline.Sub(now) < 90*time.Millisecond {
		t.Fatal("handshake did not use receipt wait")
	}
	var f *ackDelayFlow
	for _, v := range d.flows {
		f = v
	}
	ack := ackTestPacket(false, 15000, 0x10, 101)
	_, h = tcpDelayTuple(ack)
	if got := d.ackDeadline(f, h, deadline); !got.Equal(deadline) {
		t.Fatal("handshake delay added twice")
	}
}

func TestTCPAckReceiptKeepaliveAndPureACK(t *testing.T) {
	d, f, ack := receiptLab(t)
	// A normal inbound pure ACK should not hold an unrelated application reply.
	p := reverseACKPacket(ackTestPacket(false, 15000, 16, 0))
	d.observe(p)
	_, h := tcpDelayTuple(ack(0, 24))
	now := time.Now()
	if got := d.ackDeadline(f, h, now); !got.Equal(now) {
		t.Fatal("ordinary inbound ACK caused a new delay")
	}
	// Keepalive: RCV.NXT-1, no payload. Its duplicate ACK also needs the floor.
	p = reverseACKPacket(ackTestPacket(false, 15000, 16, 0xffffffff))
	d.observe(p)
	now = time.Now()
	deadline := d.ackDeadline(f, h, now)
	if deadline.Sub(now) < 90*time.Millisecond {
		t.Fatal("keepalive exposed immediate reply")
	}
	d.observe(p)
	if !f.probeUntil.Equal(deadline) {
		t.Fatal("pending probe deadline restarted")
	}
}

package freedom

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func ackTestPacket(v6 bool, port uint16, flags byte, seq uint32) []byte {
	p := delayTestPacket(v6, port, flags)
	n := 20
	if v6 {
		n = 40
	}
	binary.BigEndian.PutUint32(p[n+4:n+8], seq)
	if flags&8 != 0 {
		p = append(p, 1, 2, 3)
		if v6 {
			binary.BigEndian.PutUint16(p[4:6], 23)
		} else {
			binary.BigEndian.PutUint16(p[2:4], 43)
		}
	}
	return p
}

func TestTCPAckDelayOrderingWindowAndHandshake(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		type sent struct {
			seq uint32
			at  time.Time
		}
		output := make(chan sent, 20)
		d := newACKDelayer(ctx, &TCPAckDelay{MinMs: 60, MaxMs: 100, WindowMs: 50}, func(p []byte) { _, h := tcpDelayTuple(p); output <- sent{binary.BigEndian.Uint32(h[4:8]), time.Now()} }, nil)
		samples := []time.Duration{100 * time.Millisecond, 60 * time.Millisecond, 80 * time.Millisecond}
		i := 0
		d.sample = func() time.Duration { x := samples[i]; i++; return x }
		done := make(chan struct{})
		go func() { d.run(); close(done) }()
		submitObserved(d, ackTestPacket(v6, 14000, 2, 100))
		<-output
		start := time.Now()
		submitObserved(d, ackTestPacket(v6, 14000, 0x10, 101)) // Third handshake ACK.
		submitObserved(d, ackTestPacket(v6, 14000, 0x18, 102)) // Data-bearing ACK, must not overtake.
		submitObserved(d, ackTestPacket(v6, 14000, 0x11, 103)) // FIN+ACK is included.
		time.Sleep(65 * time.Millisecond)
		submitObserved(d, ackTestPacket(v6, 14000, 0x18, 104)) // Outside window, behind queued tail.
		for seq := uint32(101); seq <= 104; seq++ {
			select {
			case s := <-output:
				if s.seq != seq || s.at.Sub(start) < 95*time.Millisecond {
					t.Fatalf("out of order/early: %+v want %d", s, seq)
				}
			case <-time.After(time.Second):
				t.Fatal("delivery timeout")
			}
		}
		now := time.Now()
		submitObserved(d, ackTestPacket(v6, 14000, 0x18, 105))
		s := <-output
		if s.at.Sub(now) > 30*time.Millisecond {
			t.Fatal("window did not expire")
		}
		if i != 1 {
			t.Fatal("sampled delay after window", i)
		}
		cancel()
		<-done
		if len(d.queue) != 0 || len(d.flows) != 0 || d.bytes != 0 {
			t.Fatal("state leaked")
		}
	}
}

func TestTCPAckDelayIsolationResetAndReuse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := make(chan uint32, 20)
	d := newACKDelayer(ctx, &TCPAckDelay{MinMs: 100, MaxMs: 100}, func(p []byte) { _, h := tcpDelayTuple(p); output <- binary.BigEndian.Uint32(h[4:8]) }, nil)
	done := make(chan struct{})
	go func() { d.run(); close(done) }()
	submitObserved(d, ackTestPacket(false, 14000, 2, 1))
	<-output
	submitObserved(d, ackTestPacket(false, 14000, 0x18, 2))
	submitObserved(d, ackTestPacket(false, 14001, 0x10, 3)) // Unregistered flow is immediate.
	if <-output != 3 {
		t.Fatal("other flow blocked")
	}
	submitObserved(d, ackTestPacket(false, 14000, 0x14, 4)) // RST drops stale queued data.
	if <-output != 4 {
		t.Fatal("reset delayed")
	}
	submitObserved(d, ackTestPacket(false, 14000, 2, 5))
	<-output
	submitObserved(d, ackTestPacket(false, 14000, 0x18, 6))
	submitObserved(d, ackTestPacket(false, 14000, 2, 7))
	<-output // New ISN cancels old tuple.
	submitObserved(d, ackTestPacket(false, 14000, 0x10, 8))
	select {
	case n := <-output:
		if n != 8 {
			t.Fatal("stale data escaped", n)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	cancel()
	<-done
}

func TestTCPAckDelayBoundsAndParallel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	count := 0
	d := newACKDelayer(ctx, &TCPAckDelay{MinMs: 30, MaxMs: 60}, func(p []byte) {
		_, h := tcpDelayTuple(p)
		if h[13]&16 != 0 {
			mu.Lock()
			count++
			mu.Unlock()
		}
	}, nil)
	done := make(chan struct{})
	go func() { d.run(); close(done) }()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			submitObserved(d, ackTestPacket(i%2 == 0, uint16(14000+i), 2, 1))
			submitObserved(d, ackTestPacket(i%2 == 0, uint16(14000+i), 0x18, 2))
		}(i)
	}
	wg.Wait()
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	if count != 32 {
		t.Fatal(count)
	}
	mu.Unlock()
	d.mu.Lock()
	d.bytes = ackDelayTotalBytes
	for _, f := range d.flows {
		f.overflowUntil = time.Now().Add(time.Second)
	}
	d.mu.Unlock()
	submitObserved(d, ackTestPacket(false, 14001, 0x18, 3))
	d.mu.Lock()
	if d.drops != 1 {
		t.Fatal("queue limit not enforced")
	}
	d.bytes = 0
	d.mu.Unlock()
	cancel()
	<-done
}

func TestTCPAckDelayValidation(t *testing.T) {
	if ValidateTCPFingerprint(&Config{TcpAckDelay: &TCPAckDelay{}}) == nil {
		t.Fatal("missing profile")
	}
	for _, c := range []*TCPAckDelay{{MinMs: 10, MaxMs: 9}, {MaxMs: 1001}, {WindowMs: 60001}} {
		if ValidateTCPFingerprint(&Config{TcpFingerprint: "linux", TcpAckDelay: c}) == nil {
			t.Fatal("invalid range", c)
		}
	}
	d := newACKDelayer(context.Background(), &TCPAckDelay{MinMs: 80, MaxMs: 120}, nil, nil)
	if d.cfg.WindowMs != 10000 {
		t.Fatal("default window")
	}
	seen := map[time.Duration]bool{}
	for i := 0; i < 1000; i++ {
		s := d.sample()
		if s < 80*time.Millisecond || s > 120*time.Millisecond {
			t.Fatal(s)
		}
		seen[s] = true
	}
	if len(seen) < 2 {
		t.Fatal("no randomness")
	}
}

func TestTCPAckDelayCancelPendingAndIdleExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sent := 0
	d := newACKDelayer(ctx, &TCPAckDelay{MinMs: 100, MaxMs: 100}, func([]byte) { sent++ }, nil)
	submitObserved(d, ackTestPacket(false, 15000, 2, 1))
	submitObserved(d, ackTestPacket(false, 15000, 0x18, 2))
	if d.bytes == 0 {
		t.Fatal("packet not queued")
	}
	cancel()
	d.run()
	if sent != 1 || d.bytes != 0 || len(d.queue) != 0 || len(d.flows) != 0 {
		t.Fatal("canceled queue was sent or retained")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	d = newACKDelayer(ctx, &TCPAckDelay{MaxMs: 1}, func([]byte) {}, nil)
	submitObserved(d, ackTestPacket(false, 15000, 2, 1))
	for _, f := range d.flows {
		f.expiry = time.Now().Add(-time.Second)
	}
	done := make(chan struct{})
	go func() { d.run(); close(done) }()
	time.Sleep(20 * time.Millisecond)
	d.mu.Lock()
	left := len(d.flows)
	d.mu.Unlock()
	cancel()
	<-done
	if left != 0 {
		t.Fatal("expired SYN state retained")
	}
}

// Seed the SYN-ACK that a real active connection receives before sending ACKs.
func submitObserved(d *ackDelayer, p []byte) {
	d.submit(p)
	_, h := tcpDelayTuple(p)
	if h != nil && h[13]&0x12 == 2 {
		q := reverseACKPacket(p)
		_, r := tcpDelayTuple(q)
		r[13] = 0x12
		binary.BigEndian.PutUint32(r[4:8], 0xffffffff)
		binary.BigEndian.PutUint32(r[8:12], binary.BigEndian.Uint32(h[4:8])+1)
		d.observe(q)
	}
}

func reverseACKPacket(p []byte) []byte {
	q := append([]byte(nil), p...)
	a, b, n := 12, 16, 4
	if p[0]>>4 == 6 {
		a, b, n = 8, 24, 16
	}
	copy(q[a:a+n], p[b:b+n])
	copy(q[b:b+n], p[a:a+n])
	_, h := tcpDelayTuple(q)
	h[0], h[1], h[2], h[3] = h[2], h[3], h[0], h[1]
	return q
}

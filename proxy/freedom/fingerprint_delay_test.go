package freedom

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func delayTestPacket(v6 bool, port uint16, flags byte) []byte {
	n := 20
	if v6 {
		n = 40
	}
	p := make([]byte, n+20)
	if v6 {
		p[0] = 0x60
		p[6] = 6
		binary.BigEndian.PutUint16(p[4:6], 20)
		p[23] = 1
		p[39] = 2
	} else {
		p[0] = 0x45
		p[9] = 6
		binary.BigEndian.PutUint16(p[2:4], 40)
		p[15] = 1
		p[19] = 2
	}
	binary.BigEndian.PutUint16(p[n:n+2], 443)
	binary.BigEndian.PutUint16(p[n+2:n+4], port)
	p[n+12] = 0x50
	p[n+13] = flags
	return p
}

func TestTCPHandshakeDelay(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		p := delayTestPacket(v6, 12000, 0xd2)
		key, ok := synACKTuple(p)
		if !ok {
			t.Fatal("SYN ACK not parsed")
		}
		got := make(chan []byte, 16)
		d := &synACKDelayer{pending: make(map[synACKFlow]*delayedSYNACK), inject: func(b []byte) { got <- b }}
		d.mu.Lock()
		stop := d.registerLocked(context.Background(), key, 80*time.Millisecond)
		d.mu.Unlock()
		start := time.Now()
		if !d.enqueue(p) {
			t.Fatal("not delayed")
		}
		p[len(p)-1] = 99 // Reader buffer reuse must not corrupt the queued copy.
		if d.enqueue(delayTestPacket(v6, 12000, 0x10)) {
			t.Fatal("ordinary ACK delayed")
		}
		if d.enqueue(delayTestPacket(v6, 12001, 0x12)) {
			t.Fatal("unregistered flow delayed")
		}
		for i := 0; i < 20; i++ {
			d.enqueue(delayTestPacket(v6, 12000, 0x12))
		}
		select {
		case b := <-got:
			if time.Since(start) < 75*time.Millisecond || b[len(b)-1] != 0 {
				t.Fatal("early delivery or corrupted packet")
			}
		case <-time.After(time.Second):
			t.Fatal("delivery timeout")
		}
		stop()
		if len(got) != 7 {
			t.Fatalf("bounded queue: %d", len(got)+1)
		}
		if d.enqueue(p) {
			t.Fatal("completed dial still delayed")
		}
	}
}

func TestTCPHandshakeDelayCancellationAndConcurrency(t *testing.T) {
	var mu sync.Mutex
	count := 0
	d := &synACKDelayer{pending: make(map[synACKFlow]*delayedSYNACK), inject: func([]byte) { mu.Lock(); count++; mu.Unlock() }}
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		p := delayTestPacket(i%2 == 0, uint16(12000+i), 0x12)
		key, _ := synACKTuple(p)
		d.mu.Lock()
		stop := d.registerLocked(context.Background(), key, 100*time.Millisecond)
		d.mu.Unlock()
		d.enqueue(p)
		wg.Add(1)
		go func(cancel bool) {
			defer wg.Done()
			if !cancel {
				time.Sleep(160 * time.Millisecond)
			}
			stop()
		}(i%2 == 0)
	}
	wg.Wait()
	if time.Since(start) > time.Second {
		t.Fatal("flows serialized")
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 16 || len(d.pending) != 0 {
		t.Fatalf("delivery/cleanup: count=%d pending=%d", count, len(d.pending))
	}
	// An old canceled tuple must not affect a new connection using that tuple.
	p := delayTestPacket(false, 15000, 0x12)
	key, _ := synACKTuple(p)
	d.mu.Lock()
	stop := d.registerLocked(context.Background(), key, time.Second)
	d.mu.Unlock()
	stop()
	d.mu.Lock()
	stop = d.registerLocked(context.Background(), key, 0)
	d.mu.Unlock()
	if d.enqueue(p) {
		t.Fatal("zero delay queued")
	}
	stop()
}

func TestTCPHandshakeDelayValidation(t *testing.T) {
	for _, r := range []*TCPHandshakeDelay{{MinMs: 101, MaxMs: 100}, {MaxMs: 10001}} {
		if ValidateTCPFingerprint(&Config{TcpFingerprint: "windows", TcpHandshakeDelay: r}) == nil {
			t.Fatal("invalid range accepted")
		}
	}
	if ValidateTCPFingerprint(&Config{TcpHandshakeDelay: &TCPHandshakeDelay{}}) == nil {
		t.Fatal("missing fingerprint accepted")
	}
	r := &TCPHandshakeDelay{MinMs: 80, MaxMs: 120}
	seen := map[time.Duration]bool{}
	for i := 0; i < 1000; i++ {
		v := randomHandshakeDelay(r)
		if v < 80*time.Millisecond || v > 120*time.Millisecond {
			t.Fatal(v)
		}
		seen[v] = true
	}
	if len(seen) < 2 {
		t.Fatal("not randomized")
	}
	if randomHandshakeDelay(&TCPHandshakeDelay{MinMs: 100, MaxMs: 100}) != 100*time.Millisecond {
		t.Fatal("fixed delay")
	}
}

func TestTCPHandshakeDelayParser(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		p := delayTestPacket(v6, 12000, 0x12)
		for i := 0; i < len(p); i++ {
			if _, ok := synACKTuple(p[:i]); ok {
				t.Fatal("truncation accepted", i)
			}
		}
		for _, flags := range []byte{2, 0x10, 0x14, 0x13} {
			if _, ok := synACKTuple(delayTestPacket(v6, 12000, flags)); ok {
				t.Fatal("non SYN ACK accepted")
			}
		}
	}
	p := delayTestPacket(true, 12000, 0x12)
	p = append(p[:40], append(make([]byte, 8), p[40:]...)...)
	p[6] = 60
	p[40] = 6
	binary.BigEndian.PutUint16(p[4:6], 28)
	if _, ok := synACKTuple(p); !ok {
		t.Fatal("IPv6 extension rejected")
	}
	p[6] = 44
	if _, ok := synACKTuple(p); ok {
		t.Fatal("fragment accepted")
	}
	p = delayTestPacket(false, 12000, 0x12)
	p[6] = 0x20
	if _, ok := synACKTuple(p); ok {
		t.Fatal("IPv4 fragment accepted")
	}
}

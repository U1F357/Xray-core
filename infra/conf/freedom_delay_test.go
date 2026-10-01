package conf

import (
	"encoding/json"
	"github.com/xtls/xray-core/proxy/freedom"
	"testing"
)

func TestFreedomHandshakeDelayJSON(t *testing.T) {
	var c FreedomConfig
	if err := json.Unmarshal([]byte(`{"tcpFingerprint":"windows","tcpHandshakeDelay":{"minMs":80,"maxMs":120}}`), &c); err != nil {
		t.Fatal(err)
	}
	p, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	r := p.(*freedom.Config).TcpHandshakeDelay
	if r == nil || r.MinMs != 80 || r.MaxMs != 120 {
		t.Fatalf("range lost: %v", r)
	}
	for _, s := range []string{`{"minMs":-1,"maxMs":10}`, `{"minMs":0.5,"maxMs":10}`} {
		if json.Unmarshal([]byte(s), &TCPHandshakeDelay{}) == nil {
			t.Fatal("invalid milliseconds accepted")
		}
	}
}

func TestFreedomAckDelayJSON(t *testing.T) {
	var c FreedomConfig
	if err := json.Unmarshal([]byte(`{"tcpFingerprint":"auto","tcpAckDelay":{"minMs":80,"maxMs":120,"windowMs":10000}}`), &c); err != nil {
		t.Fatal(err)
	}
	p, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	a := p.(*freedom.Config).TcpAckDelay
	if a == nil || a.MinMs != 80 || a.MaxMs != 120 || a.WindowMs != 10000 {
		t.Fatal(a)
	}
}

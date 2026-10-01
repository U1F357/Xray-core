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

func TestFreedomAckDelayContinuousJSON(t *testing.T) {
	var c FreedomConfig
	if err := json.Unmarshal([]byte(`{"tcpFingerprint":"auto","tcpAckDelay":{"minMs":100,"maxMs":100,"continuous":true}}`), &c); err != nil {
		t.Fatal(err)
	}
	p, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !p.(*freedom.Config).TcpAckDelay.Continuous {
		t.Fatal("continuous lost")
	}
	c.TCPAckDelay.WindowMs = 10000
	if _, err := c.Build(); err == nil {
		t.Fatal("ambiguous duration accepted")
	}
}

func TestFreedomAutoRTTJSON(t *testing.T) {
	for _, tc := range []struct {
		config   string
		manual   bool
		min, max uint32
		fail     bool
	}{
		{`{"autoRTT":{}}`, false, 0, 1000, false},
		{`{"autoRTT":{"minMs":5,"maxMs":300,"fallbackMs":50},"continuous":true}`, false, 5, 300, false},
		{`{"autoRTT":{},"minMs":80,"maxMs":120}`, true, 80, 120, false},
		{`{"autoRTT":{},"minMs":0,"maxMs":0}`, true, 0, 0, false},
		{`{"autoRTT":{"minMs":200,"fallbackMs":100}}`, false, 0, 0, true},
		{`{"autoRTT":{"maxMs":1001}}`, false, 0, 0, true},
		{`{"autoRTT":{},"continuous":true,"windowMs":10000}`, false, 0, 0, true},
	} {
		var c FreedomConfig
		if err := json.Unmarshal([]byte(`{"tcpFingerprint":"windows","tcpAckDelay":`+tc.config+`}`), &c); err != nil {
			t.Fatal(err)
		}
		p, err := c.Build()
		if tc.fail {
			if err == nil {
				t.Fatal("accepted", tc.config)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		a := p.(*freedom.Config).TcpAckDelay
		if tc.manual {
			if a.AutoRtt != nil || a.MinMs != tc.min || a.MaxMs != tc.max {
				t.Fatal(a)
			}
		} else if a.AutoRtt == nil || a.AutoRtt.MinMs != tc.min || a.AutoRtt.MaxMs != tc.max {
			t.Fatal(a)
		}
	}
}

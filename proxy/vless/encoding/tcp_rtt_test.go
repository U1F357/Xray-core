package encoding

import (
	"bytes"
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"testing"
)

func TestTCPRTTWireAndTrust(t *testing.T) {
	for _, us := range []uint32{0, 1, 100001, ^uint32(0)} {
		b := buf.New()
		if err := EncodeHeaderAddons(b, &Addons{TcpRtt: EncodeTCPRTT(us)}); err != nil {
			t.Fatal(err)
		}
		scratch := buf.New()
		a, err := DecodeHeaderAddons(scratch, bytes.NewReader(b.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		value, ok := DecodeTCPRTT(a.TcpRtt)
		if !ok || value != us {
			t.Fatal(value, ok)
		}
		b.Release()
		scratch.Release()
	}
	for _, tc := range []struct {
		name, source, missing, user string
		enabled                     bool
		data                        []byte
		want                        uint32
		origin                      string
	}{
		{"trusted", "vless", "", "relay", true, EncodeTCPRTT(100000), 100000, "vless"},
		{"untrusted", "vless", "", "attacker", true, EncodeTCPRTT(100000), 0, "unknown"},
		{"off", "vless", "", "relay", false, EncodeTCPRTT(100000), 0, ""},
		{"missing", "vless", "", "relay", true, nil, 0, "unknown"},
		{"fallback", "vless", "syn", "relay", true, nil, 1000, "tcp_info"},
		{"explicit unknown", "vless", "syn", "relay", true, EncodeTCPRTT(0), 0, "vless"},
		{"malformed", "vless", "", "relay", true, []byte("bad"), 0, "unknown"},
		{"ingress observation wins", "syn", "", "relay", true, EncodeTCPRTT(100000), 1000, "tcp_info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := &session.Inbound{TCPRTTUs: 1000, TCPRTTSource: "tcp_info"}
			ctx := session.ContextWithInbound(context.Background(), in)
			ctx = session.ContextWithTCPFingerprintPolicy(ctx, &session.TCPFingerprintPolicy{Source: tc.source, OnMissing: tc.missing, RTT: tc.enabled, TrustedUsers: []string{"relay"}})
			ApplyTCPFingerprint(ctx, &Addons{TcpRtt: tc.data}, tc.user)
			if in.TCPRTTUs != tc.want || in.TCPRTTSource != tc.origin {
				t.Fatalf("%+v", in)
			}
		})
	}
}

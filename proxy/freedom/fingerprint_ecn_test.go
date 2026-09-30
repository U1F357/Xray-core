package freedom

import (
	"context"
	"github.com/xtls/xray-core/common/session"
	"testing"
)

func TestFingerprintECNSelection(t *testing.T) {
	for _, profile := range []string{"windows", "macos", "linux"} {
		template := "classic"
		if profile == "linux" {
			template = "none"
		}
		for _, mode := range []string{"", "none", "classic", "accecn", "invalid"} {
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{TCPECN: mode, TCPECNSource: "vless"})
			got, source, fallback := selectFingerprintECN(ctx, "auto", profile)
			known := mode == "none" || mode == "classic" || mode == "accecn"
			want := mode
			if !known {
				want = template
			}
			if got != want || fallback == known || known && source != "vless" {
				t.Fatalf("profile=%s mode=%s got=%s source=%s fallback=%v", profile, mode, got, source, fallback)
			}
			for _, fixed := range []string{"none", "classic", "accecn"} {
				got, source, fallback = selectFingerprintECN(ctx, fixed, profile)
				if got != fixed || source != "fixed" || fallback {
					t.Fatal("peer overrode fixed configuration")
				}
			}
		}
	}
	for _, mode := range []string{"template", "auto", "none", "classic", "accecn"} {
		if err := ValidateTCPFingerprint(&Config{TcpEcn: mode}); err == nil {
			t.Fatal("accepted ECN without fingerprint")
		}
		c := &Config{TcpFingerprint: "windows", TcpEcn: mode}
		if err := ValidateTCPFingerprint(c); err != nil {
			t.Fatal(err)
		}
		if c.RequiresTCPFingerprintCapture() != (mode == "auto") {
			t.Fatal("ECN auto did not request capture")
		}
	}
	if err := ValidateTCPFingerprint(&Config{TcpFingerprint: "windows", TcpEcn: "invalid"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

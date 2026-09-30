package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestFingerprintInboundPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy string
		valid  bool
	}{
		{`{"source":"syn"}`, true},
		{`{"source":"off"}`, true},
		{`{"source":"vless","trustedUsers":["relay@test"]}`, true},
		{`{"source":"vless","trustedUsers":["relay@test"],"onMissing":"syn"}`, true},
		{`{"source":"vless"}`, false},
		{`{"source":"vless","trustedUsers":["*"]}`, false},
		{`{"source":"vless","trustedUsers":[""]}`, false},
		{`{"source":"syn","trustedUsers":["relay@test"]}`, false},
		{`{"source":"off","onMissing":"syn"}`, false},
		{`{"source":"vless","trustedUsers":["relay@test"],"onMissing":"guess"}`, false},
		{`{"source":"auto"}`, false},
	} {
		var c conf.InboundDetourConfig
		input := `{"listen":"127.0.0.1","port":12345,"protocol":"vless","settings":{"clients":[{"id":"8e023ca4-6e4d-47ab-9f38-233a67d95671"}],"decryption":"none"},"tcpFingerprint":` + tc.policy + `}`
		if err := json.Unmarshal([]byte(input), &c); err != nil {
			t.Fatal(err)
		}
		_, err := c.Build()
		if (err == nil) != tc.valid {
			t.Fatalf("policy %s: %v", tc.policy, err)
		}
		if tc.valid && c.TCPFingerprint.Source == "vless" {
			c.Protocol = "socks"
			if _, err = c.Build(); err == nil {
				t.Fatal("accepted VLESS trust on non-VLESS inbound")
			}
		}
	}
}
func TestFingerprintVLESSMuxRejected(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var c conf.OutboundDetourConfig
		input := `{"protocol":"vless","settings":{"tcpFingerprintForward":true,"vnext":[{"address":"127.0.0.1","port":12345,"users":[{"id":"8e023ca4-6e4d-47ab-9f38-233a67d95671","encryption":"none"}]}]},"mux":{"enabled":` + map[bool]string{false: "false", true: "true"}[enabled] + `}}`
		if err := json.Unmarshal([]byte(input), &c); err != nil {
			t.Fatal(err)
		}
		_, err := c.Build()
		if (err != nil) != enabled {
			t.Fatalf("mux=%v: %v", enabled, err)
		}
	}
}

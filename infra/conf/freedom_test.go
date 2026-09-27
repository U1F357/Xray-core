package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestFreedomTCPFingerprint(t *testing.T) {
	automatic, err := (&FreedomConfig{TCPFingerprint: "windows"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if automatic.(*freedom.Config).TcpFingerprintSettings != nil {
		t.Fatal("automatic mode unexpectedly requires settings")
	}
	for _, profile := range []string{"windows", "macos", "linux"} {
		var c FreedomConfig
		input := `{"tcpFingerprint":"` + profile + `","tcpFingerprintSettings":{"tun":"xrfp0","address":"10.203.0.2"}}`
		if err := json.Unmarshal([]byte(input), &c); err != nil {
			t.Fatal(err)
		}
		built, err := c.Build()
		if err != nil {
			t.Fatal(err)
		}
		fc := built.(*freedom.Config)
		if fc.TcpFingerprint != profile || fc.TcpFingerprintSettings.Tun != "xrfp0" || fc.TcpFingerprintSettings.Address != "10.203.0.2" {
			t.Fatalf("incorrect config: %v", fc)
		}
	}
	for _, input := range []string{`{"tcpFingerprint":"invalid"}`, `{"tcpFingerprint":"windows","tcpFingerprintSettings":{}}`, `{"tcpFingerprintSettings":{"tun":"xrfp0","address":"10.203.0.2"}}`} {
		var c FreedomConfig
		if err := json.Unmarshal([]byte(input), &c); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Build(); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestFreedomConfig(t *testing.T) {
	creator := func() Buildable {
		return new(FreedomConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"redirect": "127.0.0.1:3366",
				"userLevel": 1
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				DomainStrategy: internet.DomainStrategy_AS_IS,
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Ip{
								Ip: []byte{127, 0, 0, 1},
							},
						},
						Port: 3366,
					},
				},
				UserLevel: 1,
			},
		},
		{
			Input: `{
				"finalRules": [{
					"action": "block",
					"network": "tcp,udp",
					"port": "53,443",
					"ip": ["10.0.0.0/8", "2001:db8::/32"],
					"blockDelay": "30-60"
				}, {
					"action": "allow",
					"network": ["udp"]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{
					{
						Action:   freedom.RuleAction_Block,
						Networks: []net.Network{net.Network_TCP, net.Network_UDP},
						PortList: &net.PortList{
							Range: []*net.PortRange{
								{From: 53, To: 53},
								{From: 443, To: 443},
							},
						},
						Ip: []*geodata.IPRule{
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{
											Ip:     []byte{10, 0, 0, 0},
											Prefix: 8,
										},
									},
								},
							},
							{
								Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{
										Cidr: &geodata.CIDR{
											Ip:     net.ParseAddress("2001:db8::").IP(),
											Prefix: 32,
										},
									},
								},
							},
						},
						BlockDelay: &freedom.Range{
							Min: 30,
							Max: 60,
						},
					},
					{
						Action:   freedom.RuleAction_Allow,
						Networks: []net.Network{net.Network_UDP},
					},
				},
			},
		},
	})
}

func TestFreedomTCPFingerprintAuto(t *testing.T) {
	var c FreedomConfig
	if err := json.Unmarshal([]byte(`{"tcpFingerprint":"AUTO","tcpFingerprintFallback":"MACOS"}`), &c); err != nil {
		t.Fatal(err)
	}
	built, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	fc := built.(*freedom.Config)
	if fc.TcpFingerprint != "auto" || fc.TcpFingerprintFallback != "macos" {
		t.Fatalf("incorrect config: %v", fc)
	}
	for _, input := range []string{`{"tcpFingerprintFallback":"linux"}`, `{"tcpFingerprint":"auto","tcpFingerprintFallback":"native"}`, `{"tcpFingerprint":"auto","tcpFingerprintSettings":{"tun":"fp0","address":"10.0.0.2"}}`} {
		var invalid FreedomConfig
		if err := json.Unmarshal([]byte(input), &invalid); err != nil {
			t.Fatal(err)
		}
		if _, err := invalid.Build(); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

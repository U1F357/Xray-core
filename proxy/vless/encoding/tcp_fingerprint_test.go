package encoding

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/dynamicpb"
)

func TestFingerprintVLESSWireCompatibility(t *testing.T) {
	for _, flow := range []string{"", vless.XRV} {
		for _, profile := range []string{"", "windows", "macos", "linux"} {
			a := &Addons{Flow: flow, TcpFingerprint: EncodeTCPFingerprint(profile)}
			b := buf.New()
			if err := EncodeHeaderAddons(b, a); err != nil {
				t.Fatal(err)
			}
			scratch := buf.New()
			got, err := DecodeHeaderAddons(scratch, bytes.NewReader(b.Bytes()))
			scratch.Release()
			if err != nil {
				t.Fatal(err)
			}
			p, valid := DecodeTCPFingerprint(got.TcpFingerprint)
			if !valid || p != profile || got.Flow != flow {
				t.Fatalf("roundtrip %v", got)
			}
			// An upstream-equivalent schema (only fields 1 and 2) must decode the wire.
			fd := protodesc.ToFileDescriptorProto(File_proxy_vless_encoding_addons_proto)
			fd.MessageType[0].Field = fd.MessageType[0].Field[:2]
			fd.Name = proto.String("stock-addons.proto")
			file, err := protodesc.NewFile(fd, nil)
			if err != nil {
				t.Fatal(err)
			}
			legacy := dynamicpb.NewMessage(file.Messages().Get(0))
			if err = proto.Unmarshal(b.Bytes()[1:], legacy); err != nil {
				t.Fatal(err)
			}
			if legacy.Get(legacy.Descriptor().Fields().ByNumber(1)).String() != flow || len(legacy.GetUnknown()) == 0 {
				t.Fatal("legacy decoding changed flow or lost framing")
			}
			b.Release()
		}
	}
	b := buf.New()
	defer b.Release()
	if err := EncodeHeaderAddons(b, &Addons{}); err != nil || !bytes.Equal(b.Bytes(), []byte{0}) {
		t.Fatal("disabled extension changed ordinary VLESS")
	}
	b.Clear()
	if err := EncodeHeaderAddons(b, &Addons{Flow: vless.XRV, Seed: make([]byte, 256)}); err == nil {
		t.Fatal("accepted overflowing Addons length")
	}
}
func TestFingerprintVLESSTrustPolicy(t *testing.T) {
	valid := EncodeTCPFingerprint("windows")
	cases := []struct {
		name, source, missing, user string
		data                        []byte
		want, origin                string
	}{
		{"trusted", "vless", "", "relay", valid, "windows", "vless"},
		{"untrusted", "vless", "", "client", valid, "", "unknown"},
		{"absent", "vless", "", "relay", nil, "", "unknown"},
		{"explicit fallback", "vless", "syn", "relay", nil, "linux", "syn"},
		{"unknown preserved", "vless", "syn", "relay", EncodeTCPFingerprint(""), "", "vless"},
		{"invalid", "vless", "", "relay", []byte("bad"), "", "unknown"},
		{"observed wins", "syn", "", "relay", valid, "linux", "syn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := &session.Inbound{TCPFingerprint: "linux", TCPFingerprintSource: "syn"}
			ctx := session.ContextWithInbound(context.Background(), in)
			ctx = session.ContextWithTCPFingerprintPolicy(ctx, &session.TCPFingerprintPolicy{Source: c.source, OnMissing: c.missing, TrustedUsers: []string{"relay"}})
			ApplyTCPFingerprint(ctx, &Addons{TcpFingerprint: c.data}, c.user)
			if in.TCPFingerprint != c.want || in.TCPFingerprintSource != c.origin {
				t.Fatalf("got %s/%s", in.TCPFingerprint, in.TCPFingerprintSource)
			}
		})
	}
	for _, data := range [][]byte{nil, {}, []byte("XTFP\x02\x01"), []byte("XTFP\x01\xff"), append(valid, 0)} {
		if _, ok := DecodeTCPFingerprint(data); ok {
			t.Fatal("accepted invalid metadata")
		}
	}
}

func TestFingerprintECNWireAndTrust(t *testing.T) {
	for _, mode := range []string{"", "none", "classic", "accecn"} {
		encoded := EncodeTCPECN(mode)
		if got, ok := DecodeTCPECN(encoded); !ok || got != mode {
			t.Fatal("ECN roundtrip", got, ok)
		}
		// Encode the ECN-only extension, and let both upstream and older custom
		// schemas parse it. Neither may change flow or payload boundaries.
		for _, fields := range []int{2, 3} {
			a := &Addons{TcpFingerprint: EncodeTCPFingerprint("macos"), TcpEcn: encoded}
			b := buf.New()
			if err := EncodeHeaderAddons(b, a); err != nil {
				t.Fatal(err)
			}
			fd := protodesc.ToFileDescriptorProto(File_proxy_vless_encoding_addons_proto)
			fd.MessageType[0].Field = fd.MessageType[0].Field[:fields]
			fd.Name = proto.String("legacy-ecn.proto")
			file, err := protodesc.NewFile(fd, nil)
			if err != nil {
				t.Fatal(err)
			}
			legacy := dynamicpb.NewMessage(file.Messages().Get(0))
			if err := proto.Unmarshal(b.Bytes()[1:], legacy); err != nil {
				t.Fatal(err)
			}
			if fields == 3 {
				got, ok := DecodeTCPFingerprint(legacy.Get(legacy.Descriptor().Fields().ByNumber(65001)).Bytes())
				if !ok || got != "macos" {
					t.Fatal("old core lost OS category")
				}
			}
			b.Release()
		}
		for _, source := range []string{"syn", "vless"} {
			for _, trusted := range []bool{false, true} {
				in := &session.Inbound{TCPFingerprint: "windows", TCPFingerprintSource: "syn", TCPECN: "classic", TCPECNSource: "syn"}
				ctx := session.ContextWithInbound(context.Background(), in)
				ctx = session.ContextWithTCPFingerprintPolicy(ctx, &session.TCPFingerprintPolicy{Source: source, TrustedUsers: []string{"relay"}})
				user := "untrusted"
				if trusted {
					user = "relay"
				}
				ApplyTCPFingerprint(ctx, &Addons{TcpEcn: encoded}, user)
				want, origin := "classic", "syn"
				if source == "vless" {
					want, origin = "", "unknown"
					if trusted {
						want, origin = mode, "vless"
					}
				}
				if in.TCPECN != want || in.TCPECNSource != origin {
					t.Fatalf("source=%s trusted=%v mode=%q: %q/%s", source, trusted, mode, in.TCPECN, in.TCPECNSource)
				}
			}
		}
	}
	for _, bad := range [][]byte{nil, []byte("XECN\x02\x01"), []byte("XECN\x01\xff"), []byte("XECN\x01\x03\x00")} {
		if _, ok := DecodeTCPECN(bad); ok {
			t.Fatal("accepted malformed ECN extension")
		}
	}
}

func TestFingerprintECNMissingPolicy(t *testing.T) {
	cases := []struct {
		name                  string
		data                  []byte
		missing, want, source string
	}{
		{"missing", nil, "", "", "unknown"},
		{"missing fallback", nil, "syn", "classic", "syn"},
		{"invalid fallback", []byte("XECN\x02\x03"), "syn", "classic", "syn"},
		{"explicit unknown", EncodeTCPECN(""), "syn", "", "vless"},
		{"explicit none", EncodeTCPECN("none"), "syn", "none", "vless"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := &session.Inbound{TCPFingerprint: "linux", TCPFingerprintSource: "syn", TCPECN: "classic", TCPECNSource: "syn"}
			ctx := session.ContextWithInbound(context.Background(), in)
			ctx = session.ContextWithTCPFingerprintPolicy(ctx, &session.TCPFingerprintPolicy{Source: "vless", TrustedUsers: []string{"relay"}, OnMissing: c.missing})
			ApplyTCPFingerprint(ctx, &Addons{TcpFingerprint: EncodeTCPFingerprint("macos"), TcpEcn: c.data}, "relay")
			if in.TCPECN != c.want || in.TCPECNSource != c.source || in.TCPFingerprint != "macos" {
				t.Fatalf("got %+v", in)
			}
		})
	}
	b := buf.New()
	defer b.Release()
	if err := EncodeHeaderAddons(b, &Addons{TcpEcn: EncodeTCPECN("accecn")}); err != nil {
		t.Fatal(err)
	}
	scratch := buf.New()
	defer scratch.Release()
	a, err := DecodeHeaderAddons(scratch, bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if mode, ok := DecodeTCPECN(a.TcpEcn); !ok || mode != "accecn" || len(a.TcpFingerprint) != 0 {
		t.Fatal("ECN-only metadata lost")
	}
}

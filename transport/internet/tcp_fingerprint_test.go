package internet

import (
	"encoding/hex"
	"testing"
)

func TestTCPFingerprintClassify(t *testing.T) {
	cases := []struct{ options, profile string }{
		{"020405b40103030801010402", "windows"},
		{"020405b4010303060101080a000000010000000004020000", "macos"},
		{"020405b40402080a000000010000000001030309", "linux"},
		{"020405b40103030701010101", ""},
		{"020005b40103030801010402", ""},
		{"020405b4010303ff01010402", ""},
	}
	for _, c := range cases {
		opts, _ := hex.DecodeString(c.options)
		for _, v6 := range []bool{false, true} {
			ip := make([]byte, 20)
			ip[0] = 0x45
			ip[9] = 6
			if v6 {
				ip = make([]byte, 40)
				ip[0] = 0x60
				ip[6] = 6
			}
			tcp := make([]byte, 20)
			tcp[12] = byte((20+len(opts))/4) << 4
			tcp[13] = 2
			tcp[14] = 0xff
			tcp[15] = 0xff
			packet := append(append(ip, tcp...), opts...)
			if got := ClassifyTCPSYN(packet); got != c.profile {
				t.Fatalf("%s v6=%v: %q != %q", c.options, v6, got, c.profile)
			}
			// ECN negotiation does not change the platform-family classifier.
			for _, bits := range []uint16{0x02, 0xc2, 0x1c2} {
				packet[len(ip)+12] = tcp[12] | byte(bits>>8)
				packet[len(ip)+13] = byte(bits)
				if got := ClassifyTCPSYN(packet); got != c.profile {
					t.Fatalf("%s v6=%v flags=%#x: %q != %q", c.options, v6, bits, got, c.profile)
				}
			}
			packet[len(ip)+12], packet[len(ip)+13] = tcp[12], 2
			for n := 0; n < len(packet); n++ {
				if got := ClassifyTCPSYN(packet[:n]); got != "" {
					t.Fatalf("accepted truncated header at %d", n)
				}
			}
			packet[len(ip)+13] = 0x12
			if got := ClassifyTCPSYN(packet); got != "" {
				t.Fatal("accepted SYN ACK")
			}
		}
	}
}

func FuzzTCPFingerprint(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, b []byte) { ClassifyTCPSYN(b) })
}

func TestTCPECNClassify(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		offset := 20
		if v6 {
			offset = 40
		}
		p := make([]byte, offset+20)
		p[0] = 0x45
		p[9] = 6
		if v6 {
			p[0] = 0x60
			p[6] = 6
		}
		h := p[offset:]
		h[12] = 0x50
		h[14] = 1
		for bits := byte(0); bits < 8; bits++ {
			h[12] = 0x50 | bits>>2
			h[13] = 2 | (bits&3)<<6
			want := ""
			switch bits {
			case 0:
				want = "none"
			case 3:
				want = "classic"
			case 7:
				want = "accecn"
			}
			if got := ClassifyTCPSYNECN(p); got != want {
				t.Fatalf("v6=%v bits=%d: %q want %q", v6, bits, got, want)
			}
		}
		h[13] |= 0x10
		if got := ClassifyTCPSYNECN(p); got != "" {
			t.Fatal("accepted SYN-ACK")
		}
		h[13] = 0xc2
		h[12] = 0x53
		if got := ClassifyTCPSYNECN(p); got != "" {
			t.Fatal("accepted reserved bits")
		}
		h[12] = 0x51
		h[14], h[15] = 0, 0
		if got := ClassifyTCPSYNECN(p); got != "accecn" {
			t.Fatal("zero receive window hid ECN offer", got)
		}
		for n := 0; n < len(p); n++ {
			if got := ClassifyTCPSYNECN(p[:n]); got != "" {
				t.Fatalf("accepted truncation at %d", n)
			}
		}
	}
}

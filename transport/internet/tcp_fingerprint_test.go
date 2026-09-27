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

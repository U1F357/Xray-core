package encoding

import (
	"bytes"
	"encoding/binary"
	"github.com/xtls/xray-core/common/session"
)

var rttMagic = []byte{'X', 'R', 'T', 'T', 1}

// Zero is explicitly unknown. Preserve the initial measurement across trusted hops.
func EncodeTCPRTT(us uint32) []byte {
	b := make([]byte, 9)
	copy(b, rttMagic)
	binary.BigEndian.PutUint32(b[5:], us)
	return b
}
func DecodeTCPRTT(b []byte) (uint32, bool) {
	if len(b) != 9 || !bytes.Equal(b[:5], rttMagic) {
		return 0, false
	}
	return binary.BigEndian.Uint32(b[5:]), true
}
func applyTCPRTT(in *session.Inbound, policy *session.TCPFingerprintPolicy, addons *Addons, email string) {
	observed := in.TCPRTTUs
	in.TCPRTTUs, in.TCPRTTSource = 0, ""
	if !policy.RTT {
		return
	}
	in.TCPRTTSource = "unknown"
	if policy.OnMissing == "syn" {
		in.TCPRTTUs, in.TCPRTTSource = observed, "tcp_info"
	}
	for _, user := range policy.TrustedUsers {
		if user != "" && user == email {
			if addons != nil {
				if us, ok := DecodeTCPRTT(addons.TcpRtt); ok {
					in.TCPRTTUs, in.TCPRTTSource = us, "vless"
				}
			}
			return
		}
	}
}

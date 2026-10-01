package encoding

import (
	"bytes"
	"context"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
)

// Private, versioned wire format. Unknown versions and conflicting private
// extensions are ignored without changing VLESS flow or payload framing.
var fingerprintMagic = []byte{'X', 'T', 'F', 'P', 1}

func EncodeTCPFingerprint(profile string) []byte {
	code := byte(0)
	switch profile {
	case "windows":
		code = 1
	case "macos":
		code = 2
	case "linux":
		code = 3
	}
	return append(append([]byte(nil), fingerprintMagic...), code)
}
func DecodeTCPFingerprint(data []byte) (string, bool) {
	if len(data) != 6 || !bytes.Equal(data[:5], fingerprintMagic) {
		return "", false
	}
	switch data[5] {
	case 0:
		return "", true
	case 1:
		return "windows", true
	case 2:
		return "macos", true
	case 3:
		return "linux", true
	default:
		return "", false
	}
}
func TCPFingerprintLabel(profile string) string {
	if profile == "" {
		return "unknown"
	}
	return profile
}
func ApplyTCPFingerprint(ctx context.Context, addons *Addons, authenticatedEmail string) {
	policy := session.TCPFingerprintPolicyFromContext(ctx)
	if policy == nil || policy.Source != "vless" {
		return
	} // SYN/off policies ignore peer claims.
	in := session.InboundFromContext(ctx)
	if in == nil {
		return
	}
	// Resolve once on the authenticated physical VLESS request before dispatch.
	// Mux children inherit this immutable selection.
	applyTCPRTT(in, policy, addons, authenticatedEmail)
	observed, observedECN := in.TCPFingerprint, in.TCPECN
	in.TCPECN, in.TCPECNSource = "", "unknown"
	in.TCPFingerprint = ""
	in.TCPFingerprintSource = "unknown"
	if policy.OnMissing == "syn" {
		in.TCPECN, in.TCPECNSource = observedECN, "syn"
		in.TCPFingerprint = observed
		in.TCPFingerprintSource = "syn"
	}
	trusted := false
	for _, u := range policy.TrustedUsers {
		if u != "" && u == authenticatedEmail {
			trusted = true
			break
		}
	}
	status := "untrusted"
	if trusted {
		status = "missing"
		if addons != nil && len(addons.TcpFingerprint) > 0 {
			status = "invalid"
			if category, ok := DecodeTCPFingerprint(addons.TcpFingerprint); ok {
				// An explicitly forwarded unknown remains unknown even with onMissing=syn.
				in.TCPFingerprint = category
				in.TCPFingerprintSource = "vless"
				status = "accepted"
			}
		}
	}
	ecnStatus := "untrusted"
	if trusted {
		ecnStatus = "missing"
		if addons != nil && len(addons.TcpEcn) > 0 {
			ecnStatus = "invalid"
			if mode, ok := DecodeTCPECN(addons.TcpEcn); ok {
				in.TCPECN, in.TCPECNSource = mode, "vless"
				ecnStatus = "accepted"
			}
		}
	}
	errors.LogInfo(ctx, "TCP fingerprint VLESS inbound: status=", status, " source=", in.TCPFingerprintSource, " category=", TCPFingerprintLabel(in.TCPFingerprint), " ecn_status=", ecnStatus, " ecn=", TCPFingerprintLabel(in.TCPECN), " ecn_source=", in.TCPECNSource, " rttUs=", in.TCPRTTUs, " rtt_source=", in.TCPRTTSource, " user=", authenticatedEmail)
}

// ECN uses its own versioned extension: older custom cores can still decode the
// unchanged platform field. Unknown is distinct from an explicit non-ECN SYN.
var ecnMagic = []byte{'X', 'E', 'C', 'N', 1}

func EncodeTCPECN(mode string) []byte {
	code := byte(0)
	switch mode {
	case "none":
		code = 1
	case "classic":
		code = 2
	case "accecn":
		code = 3
	}
	return append(append([]byte(nil), ecnMagic...), code)
}
func DecodeTCPECN(data []byte) (string, bool) {
	if len(data) != 6 || !bytes.Equal(data[:5], ecnMagic) {
		return "", false
	}
	switch data[5] {
	case 0:
		return "", true
	case 1:
		return "none", true
	case 2:
		return "classic", true
	case 3:
		return "accecn", true
	default:
		return "", false
	}
}

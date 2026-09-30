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
	observed := in.TCPFingerprint
	in.TCPFingerprint = ""
	in.TCPFingerprintSource = "unknown"
	if policy.OnMissing == "syn" {
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
	errors.LogInfo(ctx, "TCP fingerprint VLESS inbound: status=", status, " source=", in.TCPFingerprintSource, " category=", TCPFingerprintLabel(in.TCPFingerprint), " user=", authenticatedEmail)
}

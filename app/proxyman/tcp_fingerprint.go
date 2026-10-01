package proxyman

import (
	"fmt"
	"strings"
)

func ValidateTCPFingerprintPolicy(p *TCPFingerprintConfig) error {
	if p == nil {
		return nil
	}
	if p.Source == "off" && p.Rtt {
		return fmt.Errorf("tcpFingerprint rtt requires source syn or vless")
	}
	switch p.Source {
	case "syn", "off":
		if len(p.TrustedUsers) != 0 || p.OnMissing != "" {
			return fmt.Errorf("trustedUsers/onMissing require tcpFingerprint source vless")
		}
	case "vless":
		if len(p.TrustedUsers) == 0 {
			return fmt.Errorf("tcpFingerprint source vless requires explicit trustedUsers (authenticated user emails)")
		}
		for _, u := range p.TrustedUsers {
			if strings.TrimSpace(u) == "" || u == "*" {
				return fmt.Errorf("tcpFingerprint trustedUsers must contain explicit nonempty user emails")
			}
		}
		if p.OnMissing != "" && p.OnMissing != "unknown" && p.OnMissing != "syn" {
			return fmt.Errorf("tcpFingerprint onMissing must be unknown or syn")
		}
	default:
		return fmt.Errorf("tcpFingerprint source must be syn, vless or off")
	}
	return nil
}

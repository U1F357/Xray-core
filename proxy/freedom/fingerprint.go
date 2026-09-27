package freedom

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/protobuf/proto"
)

type fingerprintDialer interface {
	Dial(context.Context, net.Destination) (net.Conn, error)
	Close() error
}

// ValidateTCPFingerprint validates both JSON-built and protobuf configurations.
func ValidateTCPFingerprint(c *Config) error {
	if c.TcpFingerprintFallback != "" {
		if c.TcpFingerprint != "auto" {
			return fmt.Errorf("tcpFingerprintFallback requires tcpFingerprint auto")
		}
		switch c.TcpFingerprintFallback {
		case "windows", "macos", "linux":
		default:
			return fmt.Errorf("tcpFingerprintFallback must be windows, macos or linux")
		}
	}
	if c.TcpFingerprint == "auto" && c.TcpFingerprintSettings != nil {
		return fmt.Errorf("tcpFingerprint auto requires automatically managed networks")
	}
	if c.TcpFingerprint == "" {
		if c.TcpFingerprintSettings != nil {
			return fmt.Errorf("tcpFingerprintSettings requires tcpFingerprint")
		}
		return nil
	}
	switch c.TcpFingerprint {
	case "windows", "macos", "linux", "auto":
	default:
		return fmt.Errorf("tcpFingerprint must be windows, macos, linux or auto")
	}
	s := c.TcpFingerprintSettings
	if s == nil {
		return nil
	} // Default: automatically managed network.
	if s.Tun == "" || len(s.Tun) > 15 || strings.ContainsAny(s.Tun, "/\x00 \t\r\n") {
		return fmt.Errorf("tcpFingerprintSettings.tun must name a preconfigured Linux TUN")
	}
	a, err := netip.ParseAddr(s.Address)
	if err != nil || !a.Is4() || !a.IsGlobalUnicast() {
		return fmt.Errorf("tcpFingerprintSettings.address must be a unicast IPv4 address for netstack")
	}
	return nil
}

func validateFingerprintStream(s *internet.MemoryStreamConfig) error {
	if s == nil {
		return nil
	}
	if (s.ProtocolName != "" && s.ProtocolName != "tcp") || s.SecurityType != "" || s.Destination != nil || s.DownloadSettings != nil || s.QuicParams != nil || (s.FinalMask != nil && s.FinalMask.HasMasks()) {
		return fmt.Errorf("tcpFingerprint requires plain TCP stream settings without security, masks or destination override")
	}
	if p, ok := s.ProtocolSettings.(proto.Message); ok && !proto.Equal(p, p.ProtoReflect().Type().New().Interface()) {
		return fmt.Errorf("tcpFingerprint does not support TCP transport headers or PROXY protocol transport options")
	}
	if s.SocketSettings != nil {
		options := proto.Clone(s.SocketSettings).(*internet.SocketConfig)
		options.DomainStrategy = internet.DomainStrategy_AS_IS
		// The JSON builder populates these defaults even when omitted.
		if proto.Equal(options.HappyEyeballs, &internet.HappyEyeballsConfig{Interleave: 1, MaxConcurrentTry: 4}) {
			options.HappyEyeballs = nil
		}
		if !proto.Equal(options, &internet.SocketConfig{}) {
			return fmt.Errorf("tcpFingerprint supports only domainStrategy in sockopt; configure egress on the host TUN route")
		}
	}
	return nil
}

func (h *Handler) fingerprintAddress(ctx context.Context, address net.Address) (net.Address, error) {
	if address.Family().IsIPv4() {
		return address, nil
	}
	if !address.Family().IsDomain() {
		return nil, fmt.Errorf("tcpFingerprint currently supports IPv4 destinations only")
	}
	strategy := h.resolveStrategy
	if !strategy.HasStrategy() {
		strategy = h.config.DomainStrategy
	}
	var ips []net.IP
	var err error
	if strategy.HasStrategy() {
		ips, err = internet.LookupForIP(address.Domain(), strategy, nil)
		if err != nil && strategy.ForceIP() {
			return nil, err
		}
	}
	if !strategy.HasStrategy() || err != nil {
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip4", address.Domain())
		if err != nil {
			return nil, err
		}
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return net.IPAddress(ip4), nil
		}
	}
	return nil, fmt.Errorf("tcpFingerprint: no IPv4 address for %s", address.Domain())
}

// Profiles are immutable and have independent stacks; selection is per session.
type selectingFingerprintDialer struct {
	profiles map[string]fingerprintDialer
	fallback string
	once     sync.Once
	closeErr error
}

func newSelectingFingerprintDialer(c *Config, create func(*Config) (fingerprintDialer, error)) (fingerprintDialer, error) {
	if err := ValidateTCPFingerprint(c); err != nil {
		return nil, err
	}
	if c.TcpFingerprint != "auto" {
		dialer, err := create(c)
		if err != nil {
			return nil, err
		}
		return &loggingFingerprintDialer{fingerprintDialer: dialer, profile: c.TcpFingerprint}, nil
	}
	d := &selectingFingerprintDialer{profiles: make(map[string]fingerprintDialer), fallback: c.TcpFingerprintFallback}
	if d.fallback == "" {
		d.fallback = "linux"
	}
	for _, name := range []string{"windows", "macos", "linux"} {
		cfg := proto.Clone(c).(*Config)
		cfg.TcpFingerprint = name
		cfg.TcpFingerprintFallback = ""
		stack, err := create(cfg)
		if err != nil {
			return nil, stderrors.Join(err, d.Close())
		}
		d.profiles[name] = stack
	}
	return d, nil
}
func (d *selectingFingerprintDialer) Dial(ctx context.Context, dest net.Destination) (net.Conn, error) {
	profile := ""
	if in := session.InboundFromContext(ctx); in != nil {
		profile = in.TCPFingerprint
	}
	selected := d.profiles[profile]
	chosen := profile
	fallback := selected == nil
	if fallback {
		chosen = d.fallback
		selected = d.profiles[chosen]
	}
	if profile == "" {
		profile = "unknown"
	}
	errors.LogInfo(ctx, "TCP fingerprint freedom: mode=auto detected=", profile, " selected=", chosen, " fallback=", fallback, " template=", fingerprintTemplate(chosen), " dialing=", dest)
	return selected.Dial(ctx, dest)
}
func (d *selectingFingerprintDialer) Close() error {
	d.once.Do(func() {
		for _, name := range []string{"windows", "macos", "linux"} {
			if s := d.profiles[name]; s != nil {
				d.closeErr = stderrors.Join(d.closeErr, s.Close())
			}
		}
	})
	return d.closeErr
}

// Log the selected template at the actual dial attempt, after finalRules checks.
type loggingFingerprintDialer struct {
	fingerprintDialer
	profile string
}

func (d *loggingFingerprintDialer) Dial(ctx context.Context, dest net.Destination) (net.Conn, error) {
	errors.LogInfo(ctx, "TCP fingerprint freedom: mode=fixed selected=", d.profile, " template=", fingerprintTemplate(d.profile), " dialing=", dest)
	return d.fingerprintDialer.Dial(ctx, dest)
}
func fingerprintTemplate(profile string) string {
	switch profile {
	case "windows":
		return "64240_2-1-3-1-1-4_*_8"
	case "macos":
		return "65535_2-1-3-1-1-8-4-0-0_*_6"
	case "linux":
		return "65535_2-4-8-1-3_*_9"
	default:
		return "unknown"
	}
}

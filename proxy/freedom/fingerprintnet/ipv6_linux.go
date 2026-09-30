//go:build linux

package fingerprintnet

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Each IPv6 stack gets a separate ULA /126. NAT66 selects the egress interface's
// address; no public prefix, NDP proxy or host default route is required.
func allocateAddress6(r *registry) (net.IP, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	addresses, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 1024; attempt++ {
		host := make(net.IP, 16)
		if _, err := rand.Read(host); err != nil {
			return nil, err
		}
		host[0] = 0xfd
		host[15] = host[15]&252 | 1
		subnet := &net.IPNet{IP: host.Mask(net.CIDRMask(126, 128)), Mask: net.CIDRMask(126, 128)}
		conflict := false
		for _, route := range routes {
			if route.Dst == nil {
				continue
			}
			bits, _ := route.Dst.Mask.Size()
			if bits != 0 && (route.Dst.Contains(host) || subnet.Contains(route.Dst.IP)) {
				conflict = true
				break
			}
		}
		for _, address := range addresses {
			if subnet.Contains(address.IP) || address.IPNet.Contains(host) {
				conflict = true
				break
			}
		}
		for _, o := range r.Owners {
			if subnet.Contains(net.ParseIP(o.Address)) {
				conflict = true
				break
			}
		}
		if !conflict {
			return host, nil
		}
	}
	return nil, fmt.Errorf("no unused IPv6 ULA /126 subnet found for automatic TCP networking")
}

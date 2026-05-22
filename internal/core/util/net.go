package util

import (
	"net"
	"net/netip"
)

func NetIPtoNetIPPRefix(ips []net.IP) []netip.Prefix {
	addrs := make([]netip.Prefix, 0, len(ips))

	for _, ip := range ips {
		if ip == nil {
			continue
		}

		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}

		var prefix netip.Prefix

		if !addr.Is4() {
			continue
		}
		prefix = netip.PrefixFrom(addr, 32)
		addrs = append(addrs, prefix)
	}

	return addrs
}

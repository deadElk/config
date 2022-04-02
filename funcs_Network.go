package main

import (
	"net/netip"
)

func netip_Addr_Prefix(inbound *netip.Addr) (outbound netip.Prefix) {
	return parse_interface((*inbound).Prefix((*inbound).BitLen())).(netip.Prefix)
}
func get_IP_Bits(inbound netip.Addr) (outbound _INet_Routing) {
	switch flag, flag4, flag6 := inbound.IsValid(), inbound.Is4(), inbound.Is6(); { // todo IP.Unmap()?
	case flag && flag4:
		return 32
	case flag && flag6:
		return 128
	}
	return
}
func get_IPPrefix_Bits(inbound netip.Prefix) (outbound _INet_Routing) {
	return get_IP_Bits(inbound.Addr())
}

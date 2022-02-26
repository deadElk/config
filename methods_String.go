package main

import (
	"strconv"
)

func (inbound _Action) String() string {
	return string(inbound)
}
func (inbound _Type) String() string {
	return string(inbound)
}
func (inbound _Service) String() string {
	return string(inbound)
}
func (inbound _Protocol) String() string {
	return string(inbound)
}
func (inbound _ASN) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _VI_ID) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _VI_Peer_ID) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _Port) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _Route_Weight) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _Default) String() string {
	return string(inbound)
}
func (inbound _Name) String() string {
	return string(inbound)
}
func (inbound _Mask) String() string {
	return string(inbound)
}
func (inbound _Content) String() string {
	return string(inbound)
}
func (inbound _Secret) String() string {
	return string(inbound)
}
func (inbound _PName) String() string {
	return string(inbound)
}
func (inbound _Mode) String() string {
	return string(inbound)
}
func (inbound _FQDN) String() string {
	return string(inbound)
}
func (inbound _netip_Prefix) String() string {
	return string(parse_interface(inbound.MarshalText()).([]byte))
}
func (inbound _netip_Addr) String() string {
	return string(parse_interface(inbound.MarshalText()).([]byte))
}

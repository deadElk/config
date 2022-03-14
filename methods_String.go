package main

import (
	"encoding/hex"
	"strconv"
	"strings"
)

func (receiver _hash_ID) String() string {
	return strings.ToUpper(hex.EncodeToString(receiver[:]))
}
func (receiver _ID) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _IDName) String() string {
	return string(receiver)
}
func (receiver _ASN) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _W) String() string {
	return string(receiver)
}
func (receiver _Communication) String() string {
	return string(receiver)
}
func (receiver _Content) String() string {
	return string(receiver)
}
func (receiver _S) String() string {
	return string(receiver)
}
func (receiver _Description) String() string {
	return string(receiver)
}
func (receiver _FQDN) String() string {
	return string(receiver)
}
func (receiver _Mask) String() string {
	return string(receiver)
}
func (receiver _Name) String() string {
	return string(receiver)
}
func (receiver _PName) String() string {
	return string(receiver)
}
func (receiver _Port) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _Protocol) String() string {
	return string(receiver)
}
func (receiver _Route_Weight) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _Secret) String() string {
	return string(receiver)
}
func (receiver _Service) String() string {
	return string(receiver)
}
func (receiver _Type) String() string {
	return string(receiver)
}
func (receiver _VI_ID) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _VI_Peer_ID) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _netip_Prefix) String() string {
	return string(parse_interface(receiver.MarshalText()).([]byte))
}
func (receiver _netip_Addr) String() string {
	return string(parse_interface(receiver.MarshalText()).([]byte))
}

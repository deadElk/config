package main

import (
	"net/netip"
)

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.

// Why return String() "invalid IP"???? What for???? Why not just return an empty String() "" ????
type _netip_Prefix struct {
	netip.Prefix
}
type _netip_Addr struct {
	netip.Addr
}

type _Service_Attributes struct {
	Description _Description `xml:"description,attr"`
	Deactivate  bool         `xml:"deactivate,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Verbosity   string       `xml:"verbosity,attr"`
	Patch       string       `xml:"patch,attr"`
	Disable     bool         `xml:"disable,attr"`
}
type _Host_Inbound_Traffic struct {
	Services  map[_Service]bool  `xml:"service,attr"`
	Protocols map[_Protocol]bool `xml:"protocol,attr"`
}
type _GT_Action struct {
	GT_Action       interface{}
	GT_Action_Value interface{}
}

type _ASN uint32
type _Action string
type _Communication string
type _Default string
type _Description string
type _FQDN string
type _Content string
type _Mask string
type _Name string
type _PName string
type _Protocol string
type _Secret string
type _Service string
type _Type string
type _VI_ID uint16
type _VI_Peer_ID uint16
type _Port uint16
type _Route_Weight uint32

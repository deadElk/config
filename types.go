package main

import (
	"net/netip"
)

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.

type _ASN uint32
type _Action string
type _Communication string
type _Content string
type _Default string
type _Description string
type _FQDN string
type _Mask string
type _Name string
type _PName string
type _Port uint16
type _Protocol string
type _Route_Weight uint32
type _Secret string
type _Service string
type _Type string
type _VI_ID uint16
type _VI_Peer_ID uint16

// Why return String() "invalid IP"???? What for???? Why not just return an empty String() "" ????
type _netip_Prefix struct {
	netip.Prefix
}
type _netip_Addr struct {
	netip.Addr
}

type Attribute_List struct {
	Description _Description `xml:"description,attr"`
	Deactivate  bool         `xml:"deactivate,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Verbosity   string       `xml:"verbosity,attr"`
	Patch       string       `xml:"patch,attr"`
	Disable     bool         `xml:"disable,attr"`
}
type Host_Inbound_Traffic_List struct {
	Services  map[_Service]bool  `xml:"service,attr"`
	Protocols map[_Protocol]bool `xml:"protocol,attr"`
	// GT_Action map[interface{}][]string
	GT_Action_List
}
type GT_Action_List struct {
	GT_Action string
}

type IKE_Option_List struct {
	IKE_GCM    bool
	IKE_No_NAT bool
}

type SP_Option_List struct {
	SP_Default_Policy _Action
}

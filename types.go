package main

import (
	"net/netip"

	log "github.com/sirupsen/logrus"
)

type _hash_ID [_hash_Size]uint8 // _hash_ID here is a result of sha3.Sum512.
type _ID uint
type _IDName string

type _ASN uint32
type _W string
type _Communication string
type _Content string
type _S string
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

type _GT_Action_List map[interface{}][]string

// Why return String() "invalid IP"???? What for???? Why not just return an empty String() "" ????
type _netip_Prefix struct {
	netip.Prefix
}
type _netip_Addr struct {
	netip.Addr
}

type _Attribute_List struct {
	Description _Description `xml:"description,attr"`
	Deactivate  bool         `xml:"deactivate,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Verbosity   log.Level    `xml:"verbosity,attr"`
	Patch       string       `xml:"patch,attr"`
	Disable     bool         `xml:"disable,attr"`
}

type _Host_Inbound_Traffic_List struct {
	Services  map[_Service]bool  `xml:"service,attr"`
	Protocols map[_Protocol]bool `xml:"protocol,attr"`
	GT_Action string
}

// type _GT_Action_List struct {
// 	GT_Action string
// }

type _IKE_Option_List struct {
	IKE_GCM    bool
	IKE_No_NAT bool
	GT_Action  string
}

type _SP_Option_List struct {
	Default_Policy _W
	GT_Action      string
}

type _BGP struct {
	BGP_Group map[_Name]_BGP_Group
	GT_Action string
	_Attribute_List
}
type _BGP_Group struct {
	Local_ASN  _ASN
	Remote_ASN _ASN
	Passive    bool
	// 	Type      _Type
	// 	Multipath bool
	Neighbor  map[netip.Addr]_BGP_Group_Neighbor
	GT_Action string
	_Attribute_List
}
type _BGP_Group_Neighbor struct {
	Local_ASN  _ASN
	Remote_ASN _ASN
	Passive    bool
	Local_IP   netip.Addr
	Route_Leak map[_W]i_Route_Leak_FromTo
	GT_Action  string
	_Attribute_List
}

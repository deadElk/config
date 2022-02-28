package main

import (
	"net/netip"
)

type _i_ab map[_Name]i_AB
type _i_ja map[_Name]i_JA
type _i_pl map[_Name]i_PO_PL
type _i_ps map[_Name]i_PO_PS
type _i_peer map[_ASN]i_Peer
type _i_vi map[_VI_ID]i_VI
type _i_vi_peer map[_VI_ID]map[_VI_Peer_ID]i_VI_Peer
type _i_gt map[_Name]i_GT
type _i_config map[_ASN][]byte

// Templates
type i_GT struct {
	Content _Content
	_Service_Attributes
}

// Peer
type i_Peer struct {
	PName         _PName
	Router_ID     netip.Addr
	IF_2_RI       map[_Name]_Name // interface to RI mapping. interfaces within one peer must be unique.
	VI            map[_VI_ID]*i_VI
	VI_Peer_Left  map[_VI_ID]*i_VI_Peer
	VI_Peer_Right map[_VI_ID]*i_VI_Peer
	IFM           map[_Name]i_Peer_IFM
	RI            map[_Name]i_Peer_RI
	Hostname      _FQDN
	Domain_Name   _FQDN
	Version       string
	Major         float64
	Manufacturer  string
	Model         string
	Serial        string
	Root          _Secret
	GT_List       []_Name
	SZ            map[_Name]i_SZ
	NAT           map[_Type]i_NAT
	SP_Exact      []i_Rule_Set
	SP_Global     []i_Rule
	AB            map[_Name]*i_AB
	JA            map[_Name]*i_JA
	PL            map[_Name]*i_PO_PL
	PS            map[_Name]*i_PO_PS
	i_SP_Options
	_Service_Attributes
}
type i_Peer_IFM struct {
	Communication _Communication
	_Service_Attributes
}
type i_Peer_RI struct {
	IP_2_IF map[netip.Addr]_Name // interface's ip address to interface mapping. ip addresses within one RI must be unique.
	IF      map[_Name]i_Peer_RI_IF
	RT      map[netip.Prefix]i_Peer_RI_RO_RT
	Leak    map[_Action]i_Peer_RI_RO_Leak_FromTo
	_Service_Attributes
}
type i_Peer_RI_IF struct {
	IFM           _Name
	IFsM          _Name
	Communication _Communication
	IP            map[netip.Prefix]i_Peer_RI_IF_IP
	PARP          map[netip.Addr]i_Peer_RI_IF_PARP
	_Service_Attributes
}
type i_Peer_RI_IF_IP struct {
	Masked    netip.Prefix
	Primary   bool
	Preferred bool
	NAT       netip.Addr
	DHCP      bool
	_Service_Attributes
}
type i_Peer_RI_IF_PARP struct {
	NAT netip.Addr
	_Service_Attributes
}
type i_Peer_RI_RO_RT struct {
	GW map[_Name]i_Peer_RI_RO_RT_GW
	_Service_Attributes
}
type i_Peer_RI_RO_RT_GW struct {
	IP          netip.Addr
	IF          _Name
	Table       _Name
	Action      _Action
	Action_Flag _Action
	Metric      _Route_Weight
	Preference  _Route_Weight
	_Service_Attributes
}
type i_Peer_RI_RO_Leak_FromTo struct {
	PL []_Name
	_Service_Attributes
}

// Virtual Interfaces
type i_VI struct {
	PName         _PName
	IPPrefix      netip.Prefix
	IKE_No_NAT    bool
	IKE_GCM       bool
	Type          _Type
	Communication _Communication
	Route_Metric  _Route_Weight
	PSK           _Secret
	_Service_Attributes
}
type i_VI_Peer struct {
	ASN               _ASN
	RI                _Name
	IF                _Name
	IP                netip.Addr
	NAT               netip.Addr
	IKE_Local_Address bool
	Dynamic           bool
	Inner_RI          _Name
	Inner_IP          netip.Addr
	Inner_IPPrefix    netip.Prefix
	_Service_Attributes
}

// Security
type i_SZ struct {
	Screen _Name
	IF     map[_Name]i_SZ_IF
	_Host_Inbound_Traffic
	_Service_Attributes
}
type i_SZ_IF struct {
	_Host_Inbound_Traffic
	_Service_Attributes
}
type i_NAT struct {
	Address_Persistent bool
	Pool               map[_Name]i_Pool
	Rule_Set           map[_Name]i_Rule_Set
	_Service_Attributes
}
type i_Pool struct {
	IPPrefix netip.Prefix
	RI       _Name
	SZ       _Name
	_Service_Attributes
}

// Security Rules
type i_Rule_Set struct {
	From []i_FromTo
	To   []i_FromTo
	Rule map[_Name]i_Rule
	_Service_Attributes
}
type i_FromTo struct {
	IF _Name
	SZ _Name
	RI _Name
	RG _Name
	_Service_Attributes
}
type i_Rule struct {
	Name  _Name // used only within security policies
	Match []i_Match
	Then  []i_Then
	_Service_Attributes
}
type i_Match struct {
	Application _Name
	From        []i_Match_FromTo
	To          []i_Match_FromTo
	_Service_Attributes
}
type i_Match_FromTo struct {
	SZ        _Name
	AB        _Name
	RI        _Name
	Port_Low  _Port
	Port_High _Port
	_Service_Attributes
}
type i_Then struct {
	Action      _Action
	Action_Flag _Action
	Pool        _Name
	AB          _Name
	RI          _Name
	Port_Low    _Port
	Port_High   _Port
	_Service_Attributes
}

// Address Book
type i_AB struct {
	Type        _Type
	Address     interface{}
	Address_Set map[_Name]_Type
	_Service_Attributes
}
type i_AB_Address struct {
	AB       _Name
	IPPrefix netip.Prefix
	FQDN     _FQDN
	_Service_Attributes
}

// Junos Applications
type i_JA struct {
	Term []i_JA_Term
	_Service_Attributes
}
type i_JA_Term struct {
	Name             _Name
	Protocol         _Protocol
	Destination_Port _Port
	_Service_Attributes
}

// Policy Options
type i_PO_PL struct {
	Match []i_PO_PL_Match
	_Service_Attributes
}
type i_PO_PL_Match struct {
	IPPrefix netip.Prefix
	_Service_Attributes
}
type i_PO_PS struct {
	Term []i_PO_PS_Term
	_Service_Attributes
}
type i_PO_PS_Term struct {
	Name _Name
	From []i_PO_PS_From
	Then []i_PO_PS_Then
	_Service_Attributes
}
type i_PO_PS_From struct {
	RI         _Name
	Protocol   _Protocol
	Route_Type _Type
	PL         _Name
	Mask       _Mask
	_Service_Attributes
}
type i_PO_PS_Then struct {
	Action      _Action
	Action_Flag _Action
	Metric      _Route_Weight
	_Service_Attributes
}

// Security Policies
type i_SP_Options struct {
	SP_Default_Policy _Action
}

package main

import (
	"net/netip"
)

type _i_ab map[_Name]i_AB
type _i_ja map[_Name]map[_Name]i_JA_Term
type _i_pl map[_Name][]netip.Prefix
type _i_ps map[_Name][]i_PO_PS_Term
type _i_peer map[_ASN]i_Peer
type _i_gt map[_Name]i_GT
type _i_config map[_ASN][]byte

// Templates
type i_GT struct {
	Content _Content
	_Service_Attributes
}

// Peer
type i_Peer struct {
	IFM          map[_Name]i_Peer_IFM
	RI           map[_Name]i_Peer_RI
	Hostname     _FQDN
	Domain_Name  _FQDN
	Version      string
	Manufacturer string
	Model        string
	Serial       string
	Root         _Secret
	GT_List      string
	SZ           map[_Name]i_SZ
	NAT_Source   map[_Type]i_NAT
	SP_Options   i_SP_Options
	SP_Exact     []i_Rule_Set
	SP_Global    []i_Rule
	AB           *_i_ab
	JA           *_i_ja
	PL           *_i_pl
	PS           *_i_ps
	_Service_Attributes
}
type i_Peer_RI struct {
	IF   map[_Name]i_Peer_RI_IF
	RT   map[netip.Prefix]map[_Name]i_Peer_RI_RO_RT_GW
	From []_Name
	To   []_Name
	_Service_Attributes
}
type i_Peer_IFM struct {
	Communication _Communication
	Disable       bool
	_Service_Attributes
}
type i_Peer_RI_IF struct {
	Communication _Communication
	IP            []i_Peer_RI_IF_IP
	PARP          []i_Peer_RI_IF_PARP
	Disable       bool
	_Service_Attributes
}
type i_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix
	Router_ID bool
	Primary   bool
	Preferred bool
	NAT       netip.Addr
	DHCP      bool
	_Service_Attributes
}
type i_Peer_RI_IF_PARP struct {
	IPPrefix netip.Prefix
	NAT      netip.Addr
	_Service_Attributes
}
type i_Peer_RI_RO_RT struct {
	Identifier netip.Prefix
	GW         []i_Peer_RI_RO_RT_GW
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
	PL _Name
	_Service_Attributes
}

// Virtual Interfaces
type i_VI struct {
	ID            _VI_ID
	Type          _Type
	Communication _Communication
	Route_Metric  _Route_Weight
	Peer          []i_VI_Peer
	PSK           _Secret
	_Service_Attributes
}
type i_VI_Peer struct {
	ID       _VI_Peer_ID
	ASN      _ASN
	RI       _Name
	IF       _Name
	IP       netip.Addr
	Dynamic  bool
	Inner_RI _Name
	_Service_Attributes
}

// Security
type i_SZ struct {
	Screen _Name
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
	Type      _Type
	Address   interface{}
	Addresses map[_Name]_Type
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
	Name _Name
	Term []i_JA_Term
	_Service_Attributes
}
type i_JA_Term struct {
	Protocol         _Protocol
	Destination_Port _Port
	_Service_Attributes
}

// Policy Options
type i_PO_PL struct {
	Name  _Name
	Match []i_PO_PL_Match
	_Service_Attributes
}
type i_PO_PL_Match struct {
	IPPrefix netip.Prefix
	_Service_Attributes
}
type i_PO_PS struct {
	Name _Name
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
	Default_Policy _Action
	_Service_Attributes
}

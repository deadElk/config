package main

import (
	"net/netip"
)

type _i_ab map[_Name]*i_AB
type _i_ja map[_Name]*i_JA
type _i_pl map[_Name]*i_PO_PL
type _i_ps map[_Name]*i_PO_PS
type _i_peer map[_ASN]i_Peer
type _i_vi map[_VI_ID]*i_VI
type _i_vi_peer map[_VI_ID]map[_VI_Peer_ID]*i_VI_Peer
type _i_gt map[_Name]i_GT
type _i_config map[_ASN][]byte

// 				GT_Action: []string{0: ""},

// Templates
type i_GT struct {
	Content   _Content
	GT_Action string
	_Attribute_List
}

// Peer
type i_Peer struct {
	ASN          _ASN
	PName        _PName
	Router_ID    netip.Addr
	IF_2_RI      map[_Name]_Name // interface to RI mapping. interfaces within one peer must be unique.
	VI           map[_VI_ID]*i_VI
	VI_Local     map[_VI_ID]*i_VI_Peer
	VI_Remote    map[_VI_ID]*i_VI_Peer
	VI_GT        map[_VI_ID]i_VI_GT
	IFM          map[_Name]i_Peer_IFM
	RI           map[_Name]i_Peer_RI
	Hostname     _FQDN
	Domain_Name  _FQDN
	Version      string
	Major        float64
	Manufacturer string
	Model        string
	Serial       string
	Root         _Secret
	GT_List      []_Name
	SZ           map[_Name]i_Peer_SZ
	NAT          map[_Type]i_Peer_NAT_Type
	AB           map[_Name]*i_AB
	JA           map[_Name]*i_JA
	PL           map[_Name]*i_PO_PL
	PS           map[_Name]*i_PO_PS
	SP           i_Peer_SP
	_IKE_Option_List
	GT_Action string
	_Attribute_List
}
type i_Peer_SP struct {
	Option_List _SP_Option_List
	Exact       []i_Rule_Set
	Global      []i_Rule
}
type i_Peer_IFM struct {
	Communication _Communication
	GT_Action     string
	_Attribute_List
}
type i_Peer_RI struct {
	IP_2_IF  map[netip.Addr]_Name // interface's IP address to interface mapping. IP addresses within one RI must be unique.
	IF       map[_Name]i_Peer_RI_IF
	RT       map[netip.Prefix]i_Peer_RI_RO_RT
	Leak     map[_Action]i_Route_Leak_FromTo
	Protocol map[_Name]_Name
	_BGP
	GT_Action string
	_Attribute_List
}

type i_Peer_RI_IF struct {
	IFM           _Name
	IFsM          _Name
	Communication _Communication
	IP            map[netip.Prefix]i_Peer_RI_IF_IP
	PARP          map[netip.Addr]i_Peer_RI_IF_PARP
	GT_Action     string
	_Attribute_List
}
type i_Peer_RI_IF_IP struct {
	Masked    netip.Prefix
	Primary   bool
	Preferred bool
	NAT       netip.Addr
	DHCP      bool
	GT_Action string
	_Attribute_List
}
type i_Peer_RI_IF_PARP struct {
	NAT       netip.Addr
	GT_Action string
	_Attribute_List
}
type i_Peer_RI_RO_RT struct {
	GW        map[_Name]i_Peer_RI_RO_RT_GW
	GT_Action string
	_Attribute_List
}
type i_Peer_RI_RO_RT_GW struct {
	IP          netip.Addr
	IF          _Name
	Table       _Name
	Action      _Action
	Action_Flag _Action
	Metric      _Route_Weight
	Preference  _Route_Weight
	GT_Action   string
	_Attribute_List
}
type i_Route_Leak_FromTo struct {
	PS        []_Name
	GT_Action string
	_Attribute_List
}

// Virtual Interfaces
type i_VI struct {
	PName         _PName
	IPPrefix      netip.Prefix
	Type          _Type
	Communication _Communication
	Route_Metric  _Route_Weight
	PSK           _Secret
	IKE_GCM       bool
	IKE_No_NAT    bool
	// Local          *i_VI_Peer
	// Remote         *i_VI_Peer
	// *_IKE_Option_List
	GT_Action string
	_Attribute_List
}
type i_VI_Peer struct {
	ASN               _ASN
	RI                _Name
	IF                _Name
	IP                netip.Addr
	NAT               netip.Addr
	Inner_RI          _Name
	Inner_IP          netip.Addr
	Inner_IPPrefix    netip.Prefix
	IKE_Local_Address bool
	IKE_Dynamic       bool
	// *_IKE_Option_List
	GT_Action string
	_Attribute_List
}
type i_VI_GT struct {
	PName                    _PName
	IPPrefix                 netip.Prefix
	Type                     _Type
	Communication            _Communication
	Route_Metric             _Route_Weight
	PSK                      _Secret
	IKE_GCM                  bool
	IKE_No_NAT               bool
	Local_ASN                _ASN
	Local_RI                 _Name
	Local_IF                 _Name
	Local_IP                 netip.Addr
	Local_NAT                netip.Addr
	Local_Inner_RI           _Name
	Local_Inner_IP           netip.Addr
	Local_Inner_IPPrefix     netip.Prefix
	Local_IKE_Local_Address  bool
	Local_IKE_Dynamic        bool
	Remote_ASN               _ASN
	Remote_RI                _Name
	Remote_IF                _Name
	Remote_IP                netip.Addr
	Remote_NAT               netip.Addr
	Remote_Inner_RI          _Name
	Remote_Inner_IP          netip.Addr
	Remote_Inner_IPPrefix    netip.Prefix
	Remote_IKE_Local_Address bool
	Remote_IKE_Dynamic       bool
	// Local                    *i_VI_Peer
	// Remoteп                   *i_VI_Peer
	GT_Action string
	_Attribute_List
}

// Security
type i_Peer_SZ struct {
	Screen _Name
	IF     map[_Name]i_Peer_SZ_IF
	_Host_Inbound_Traffic_List
	GT_Action string
	_Attribute_List
}
type i_Peer_SZ_IF struct {
	_Host_Inbound_Traffic_List
	GT_Action string
	_Attribute_List
}
type i_Peer_NAT_Type struct {
	Address_Persistent bool
	Pool               map[_Name]i_Pool
	Rule_Set           map[_Name]i_Rule_Set
	GT_Action          string
	_Attribute_List
}
type i_Pool struct {
	IPPrefix  netip.Prefix
	RI        _Name
	SZ        _Name
	GT_Action string
	_Attribute_List
}

// Security Rules
type i_Rule_Set struct {
	Name      _Name
	From      []i_FromTo
	To        []i_FromTo
	Rule      []i_Rule
	GT_Action string
	_Attribute_List
}
type i_FromTo struct {
	AB        _Name // NAT_Destination
	IF        _Name // NAT_Source
	RG        _Name // NAT_Source
	RI        _Name // NAT_Source
	SZ        _Name // NAT_Source
	Port_Low  _Port // NAT_Destination
	Port_High _Port // NAT_Destination
	GT_Action string
	_Attribute_List
}
type i_Rule struct {
	Name      _Name      // SP
	JA        []_Name    // SP, NAT
	From      []i_FromTo // SP, NAT
	To        []i_FromTo // SP, NAT
	Then      []i_Then   // SP, NAT
	GT_Action string
	_Attribute_List
}
type i_Then struct {
	Action      _Action
	Action_Flag _Action
	Pool        _Name
	AB          _Name
	RI          _Name
	Port_Low    _Port
	Port_High   _Port
	GT_Action   string
	_Attribute_List
}

// Address Book
type i_AB struct {
	Type      _Type
	IPPrefix  netip.Prefix
	FQDN      _FQDN
	Set       map[_Name]i_AB_Set
	GT_Action string
	_Attribute_List
}
type i_AB_Set struct {
	Type      _Type
	GT_Action string
	_Attribute_List
}

// Junos Applications (JA)
type i_JA struct {
	Term      []i_JA_Term
	GT_Action string
	_Attribute_List
}
type i_JA_Term struct {
	Name             _Name
	Protocol         _Protocol
	Destination_Port _Port
	GT_Action        string
	_Attribute_List
}

// Policy Options
type i_PO_PL struct {
	Match     []i_PO_PL_Match
	GT_Action string
	_Attribute_List
}
type i_PO_PL_Match struct {
	IPPrefix  netip.Prefix
	GT_Action string
	_Attribute_List
}
type i_PO_PS struct {
	Term      []i_PO_PS_Term
	GT_Action string
	_Attribute_List
}
type i_PO_PS_Term struct {
	Name      _Name
	From      []i_PO_PS_From
	Then      []i_PO_PS_Then
	GT_Action string
	_Attribute_List
}
type i_PO_PS_From struct {
	RI         _Name
	Protocol   _Protocol
	Route_Type _Type
	PL         _Name
	Mask       _Mask
	GT_Action  string
	_Attribute_List
}
type i_PO_PS_Then struct {
	Action      _Action
	Action_Flag _Action
	Metric      _Route_Weight
	GT_Action   string
	_Attribute_List
}

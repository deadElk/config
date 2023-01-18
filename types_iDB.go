package main

import (
	"net/netip"
)

type __ASN_Peer map[_Inet_ASN]*i_Peer
type __ASN_Peer_Group map[_Inet_ASN]*i_Peer_Group
type __INet_UI_IP_Table map[netip.Prefix]*_INet_UI_IP_Table
type __INet_VI_IP_Table map[_VI_ID]*_INet_VI_IP_Table
type __N_AB map[_Name]*i_AB
type __N_AB_Set map[_Name]*i_AB_Set
type __N_JA map[_Name]*i_JA
type __N_Name map[_Name]_Name
type __N_PO_PL map[_Name]*i_PO_PL
type __N_PO_PS map[_Name]*i_PO_PS
type __N_Peer_IFM map[_Name]*i_Peer_IFM
type __N_Peer_RI map[_Name]*i_Peer_RI
type __N_Peer_RI_IF map[_Name]*i_Peer_RI_IF
type __N_Peer_RI_RO_RT_GW map[_Name]*i_Peer_RI_RO_RT_GW
type __N_Peer_SZ map[_Name]*i_Peer_SZ
type __N_Peer_SZ_IF map[_Name]*i_Peer_SZ_IF
type __N_Pool map[_Name]*i_Pool
type __N_Rule_Set map[_Name]*i_Rule_Set
type __IPP_Peer_RI_IF map[netip.Prefix]*i_Peer_RI_IF
type __IPP_Peer_RI_IF_IP map[netip.Prefix]*i_Peer_RI_IF_IP
type __IPP_Peer_RI_IF_PARP map[netip.Prefix]*i_Peer_RI_IF_PARP
type __IPP_Peer_RI_RO_RT map[netip.Prefix]*i_Peer_RI_RO_RT
type __T_Peer_NAT_Type map[_Type]*i_Peer_NAT_Type
type __W_Route_Leak_FromTo map[_W]*i_Route_Leak_FromTo
type __FW []*i_FW
type __FW_FromTo []*i_FW_FromTo
type __FW_Term []*i_FW_Term
type __FW_Then []*i_FW_Then
type __FromTo []*i_FromTo
type __VIC_VI_Peer map[_VI_Conn_ID]*i_VI_Peer
type __JA_Term []*i_JA_Term
type __PO_PL_Match []*i_PO_PL_Match
type __PO_PS_From []*i_PO_PS_From
type __PO_PS_Term []*i_PO_PS_Term
type __PO_PS_Then []*i_PO_PS_Then
type __Rule []*i_Rule
type __Rule_Set []*i_Rule_Set
type __Then []*i_Then
type __VI_VI map[_VI_ID]*i_VI
type __VI_VI_GT map[_VI_ID]*i_VI_GT
type __VI__VIC_VI_Peer map[_VI_ID]__VIC_VI_Peer
type __VI_VI_Peer map[_VI_ID]*i_VI_Peer

// Peer Group
type i_Peer_Group struct {
	// ASN                 _Inet_ASN
	ASName              _Name
	Domain_Name         _FQDN
	GT_List             []_Name
	Host_RI             _Name
	Master_RI           _Name
	Mgmt_IF             _Name
	Mgmt_RI             _Name
	Mgmt_RI_Description _Description
	VI_RI               _Name
	PName               _PName
	SP_Default_Policy   _W
	VI_IP               __INet_VI_IP_Table
	UI_IP               __INet_UI_IP_Table
	Peer_List           __ASN_Peer
	GT_Action           string
	_Attribute_List
}

// Peer
type i_Peer struct {
	// VI           __VI_VI
	// VI_Local     __VI_VI_Peer
	// VI_Remote    __VI_VI_Peer
	Group        *i_Peer_Group
	ASN          _Inet_ASN
	ASName       _Name
	PName        _PName
	Router_ID    netip.Addr
	IF_2_RI      __N_Name // interface to RI mapping. interfaces within one peer must be unique.
	VI_GT        __VI_VI_GT
	IFM          __N_Peer_IFM
	RI           __N_Peer_RI
	Hostname     _FQDN
	Domain_Name  _FQDN
	Version      string
	Major        float64
	Manufacturer string
	Model        string
	Serial       string
	Root         _Secret
	GT_List      []_Name
	SZ           __N_Peer_SZ
	NAT          __T_Peer_NAT_Type
	AB           __N_AB
	JA           __N_JA
	PL           __N_PO_PL
	PS           __N_PO_PS
	SP           *i_Peer_SP
	FW           __FW
	IKE_GCM      bool
	GT_Action    string
	_Attribute_List
}

type i_FW struct {
	Name      _Name
	Term      __FW_Term
	GT_Action string
	_Attribute_List
}
type i_FW_Term struct {
	Name      _Name
	From      __FW_FromTo
	To        __FW_FromTo
	Then      __FW_Then
	GT_Action string
	_Attribute_List
}
type i_FW_FromTo struct {
	PL        _Name
	GT_Action string
	_Attribute_List
}
type i_FW_Then struct {
	Action      _W
	Action_Flag _W
	RI          _Name
	GT_Action   string
	_Attribute_List
}

type i_Peer_SP struct {
	Option_List *_SP_Option_List
	Exact       __Rule_Set
	Global      __Rule
	GT_Action   string
}
type i_Peer_IFM struct {
	Communication _Communication
	GT_Action     string
	_Attribute_List
}
type i_Peer_RI struct {
	IP_IF map[netip.Prefix]_Name // interface's IP address to interface mapping. IP addresses within one RI must be unique.
	// IP_IF       __IPP_Peer_RI_IF
	// IPPrefix_IF __IPP_Peer_RI_IF
	// IPMasked_IF __IPP_Peer_RI_IF
	IF         __N_Peer_RI_IF
	RT         __IPP_Peer_RI_RO_RT
	Route_Leak __W_Route_Leak_FromTo
	Protocol   __N_Name
	BGP        _BGP
	GT_Action  string
	_Attribute_List
}

type i_Peer_RI_IF struct {
	IFM           _Name
	IFsM          _Name
	Communication _Communication
	IP            __IPP_Peer_RI_IF_IP
	PARP          __IPP_Peer_RI_IF_PARP
	GT_Action     string
	_Attribute_List
}
type i_Peer_RI_IF_IP struct {
	Masked    netip.Prefix
	Primary   bool
	Preferred bool
	NAT       netip.Prefix
	DHCP      bool
	GT_Action string
	_Attribute_List
}
type i_Peer_RI_IF_PARP struct {
	NAT       netip.Prefix
	GT_Action string
	_Attribute_List
}
type i_Peer_RI_RO_RT struct {
	GW        __N_Peer_RI_RO_RT_GW
	GT_Action string
	_Attribute_List
}
type i_Peer_RI_RO_RT_GW struct {
	IP          netip.Addr
	IF          _Name
	Table       _Name
	Action      _W
	Action_Flag _W
	Metric      _INet_Routing
	Preference  _INet_Routing
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
	Route_Metric  _INet_Routing
	PSK           _Secret
	Hub           bool
	IKE_GCM       bool
	IKE_No_NAT    bool
	// Local          *i_VI_Peer
	// Remote         *i_VI_Peer
	// *_IKE_Option_List
	GT_Action string
	_Attribute_List
}
type i_VI_Peer struct {
	ASN               _Inet_ASN
	RI                _Name
	IF                _Name
	IPPrefix          netip.Prefix
	NAT               netip.Prefix
	Hub               bool
	Inner_RI          _Name
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
	Route_Metric             _INet_Routing
	PSK                      _Secret
	IKE_GCM                  bool
	IKE_No_NAT               bool
	Local_ASN                _Inet_ASN
	Local_RI                 _Name
	Local_IF                 _Name
	Local_IP                 netip.Addr
	Local_NAT                netip.Addr
	Local_Hub                bool
	Local_Inner_RI           _Name
	Local_Inner_IP           netip.Addr
	Local_Inner_IPPrefix     netip.Prefix
	Local_IKE_Local_Address  bool
	Local_IKE_Dynamic        bool
	Remote_ASN               _Inet_ASN
	Remote_RI                _Name
	Remote_IF                _Name
	Remote_IP                netip.Addr
	Remote_NAT               netip.Addr
	Remote_Hub               bool
	Remote_Inner_RI          _Name
	Remote_Inner_IP          netip.Addr
	Remote_Inner_IPPrefix    netip.Prefix
	Remote_IKE_Local_Address bool
	Remote_IKE_Dynamic       bool
	// Local                    *i_VI_Peer
	// Remote                   *i_VI_Peer
	GT_Action string
	_Attribute_List
}

// Security
type i_Peer_SZ struct {
	Screen _Name
	IF     __N_Peer_SZ_IF
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
	Pool               __N_Pool
	Rule_Set           __N_Rule_Set
	GT_Action          string
	_Attribute_List
}
type i_Pool struct {
	IPPrefix  netip.Prefix
	RI        _Name
	SZ        _Name
	Port      _INet_Port
	Port_Low  _INet_Port
	Port_High _INet_Port
	GT_Action string
	_Attribute_List
}

// Security Rules
type i_Rule_Set struct {
	Name      _Name
	From      __FromTo
	To        __FromTo
	Rule      __Rule
	GT_Action string
	_Attribute_List
}
type i_FromTo struct {
	AB        _Name      // NAT_Destination
	IF        _Name      // NAT_Source
	RG        _Name      // NAT_Source
	RI        _Name      // NAT_Source
	SZ        _Name      // NAT_Source
	Port_Low  _INet_Port // NAT_Destination
	Port_High _INet_Port // NAT_Destination
	GT_Action string
	_Attribute_List
}
type i_Rule struct {
	Name      _Name    // SP
	JA        []_Name  // SP, NAT
	From      __FromTo // SP, NAT
	To        __FromTo // SP, NAT
	Then      __Then   // SP, NAT
	GT_Action string
	_Attribute_List
}
type i_Then struct {
	Action      _W
	Action_Flag _W
	Pool        _Name
	AB          _Name
	RI          _Name
	Port_Low    _INet_Port
	Port_High   _INet_Port
	GT_Action   string
	_Attribute_List
}

// Address Book
type i_AB struct {
	Type      _Type
	IPPrefix  netip.Prefix
	FQDN      _FQDN
	Set       __N_AB_Set
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
	Term      __JA_Term
	GT_Action string
	_Attribute_List
}
type i_JA_Term struct {
	Name             _Name
	Protocol         _INet_Protocol
	Destination_Port _INet_Port
	GT_Action        string
	_Attribute_List
}

// Policy Options
type i_PO_PL struct {
	Match     __PO_PL_Match
	GT_Action string
	_Attribute_List
}
type i_PO_PL_Match struct {
	IPPrefix  netip.Prefix
	GT_Action string
	_Attribute_List
}
type i_PO_PS struct {
	Term      __PO_PS_Term
	GT_Action string
	_Attribute_List
}
type i_PO_PS_Term struct {
	Name      _Name
	From      __PO_PS_From
	Then      __PO_PS_Then
	GT_Action string
	_Attribute_List
}
type i_PO_PS_From struct {
	RI         _Name
	Protocol   _INet_Protocol
	Route_Type _Type
	PL         _Name
	Mask       _Mask
	GT_Action  string
	_Attribute_List
}
type i_PO_PS_Then struct {
	Action      _W
	Action_Flag _W
	Metric      _INet_Routing
	GT_Action   string
	_Attribute_List
}

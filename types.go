package main

import (
	"encoding/xml"
	"net/netip"
)

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.
type _service_attributes struct {
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
	// Verbosity   string       `xml:"verbosity,attr"`
}

type _AB_Type string
type _AB_Name string
type _Security_AB struct {
	Address   interface{}
	Type      _AB_Type
	Addresses map[_AB_Name]_AB_Type
	// AB       map[_AB_Name]bool
	// FQDN     map[_AB_Name]bool
	// IPPrefix map[_AB_Name]bool
	_service_attributes
}
type _Application_Name string
type _Security_Application_Term struct {
	Name             string `xml:"name,attr"`
	Protocol         string `xml:"protocol,attr"`
	Destination_Port uint16 `xml:"destination_port,attr"`
	_service_attributes
}
type _Security_NAT_Source struct {
	Address_Persistent bool                     `xml:"address_persistent,attr"`
	Pool               []_Security_NAT_Pool     `xml:"Pool"`
	Rule_Set           []_Security_NAT_Rule_Set `xml:"Rule_Set"`
	_service_attributes
}
type _Security_NAT_Destination struct {
	Pool     []_Security_NAT_Pool     `xml:"Pool"`
	Rule_Set []_Security_NAT_Rule_Set `xml:"Rule_Set"`
	_service_attributes
}
type _Security_NAT_Static struct {
	_service_attributes
}
type _Security_NAT_Pool struct {
	Name     _Pool_Name   `xml:"name,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	RI       _RI_Name     `xml:"RI,attr"`
	SZ       _SZ_Name     `xml:"SZ,attr"`
	_service_attributes
}
type _Security_NAT_Rule_Set struct {
	Name _Rule_Set_Name            `xml:"name,attr"`
	From []_Security_NAT_Direction `xml:"From"`
	To   []_Security_NAT_Direction `xml:"To"`
	Rule []_Security_NAT_Rule      `xml:"Rule"`
	_service_attributes
}
type _Security_NAT_Direction struct {
	SZ _SZ_Name `xml:"SZ,attr"`
	RI _RI_Name `xml:"RI,attr"`
	_service_attributes
}
type _Security_NAT_Rule struct {
	Name  _Rule_Name        `xml:"name,attr"`
	Match []_Security_Match `xml:"Match"`
	Then  []_Security_Then  `xml:"Then"`
	_service_attributes
}
type _Security_Match struct {
	Source      bool              `xml:"source,attr"`
	Destination bool              `xml:"destination,attr"`
	Application _Application_Name `xml:"application,attr"`
	From_SZ     _SZ_Name          `xml:"from_zone,attr"`
	To_SZ       _SZ_Name          `xml:"to_zone,attr"`
	AB          _AB_Name          `xml:"AB,attr"`
	_service_attributes
}
type _Security_Then struct {
	Source_NAT      bool       `xml:"source_NAT,attr"`
	Destination_NAT bool       `xml:"destination_NAT,attr"`
	Pool            _Pool_Name `xml:"pool,attr"`
	Permit          bool       `xml:"permit,attr"`
	Deny            bool       `xml:"deny,attr"`
	_service_attributes
}
type _Security_Policies_Exact struct {
	From   []_Security_Policies_Direction `xml:"From"`
	To     []_Security_Policies_Direction `xml:"To"`
	Policy []_Security_Policies_Policy    `xml:"Policy"`
	_service_attributes
}
type _Security_Policies_Direction struct {
	SZ _SZ_Name `xml:"SZ,attr"`
	_service_attributes
}
type _Security_Policies_Policy struct {
	Name  _Policy_Name      `xml:"name,attr"`
	Match []_Security_Match `xml:"Match"`
	Then  []_Security_Then  `xml:"Then"`
	_service_attributes
}

type _ASN uint32
type _ASN_PName string
type _Description string
type _GT_Content string
type _GT_Name string
type _GW_Name string
type _GW_Type string
type _IF_Communication string
type _IF_Mode string
type _IF_Name string
type _IFM_Name string
type _Policy string
type _Policy_Name string
type _RI_Name string
type _SZ_Name string
type _Screen_Name string
type _RM_ID [_rm_max + 1]uint32
type _Secret string
type _VI_ID uint
type _VI_ID_PName string
type _VI_Peer_ID uint
type _VI_Type string
type _Service string
type _Protocol string
type _Pool_Name string
type _Rule_Set_Name string
type _Rule_Name string
type _FQDN string
type _Host_Inbound_Traffic struct {
	Services  map[_Service]bool  `xml:"service,attr"`
	Protocols map[_Protocol]bool `xml:"protocol,attr"`
}
type _Route_Attributes struct {
	QNH        bool `xml:"QNH,attr"`
	Metric     uint `xml:"metric,attr"`
	Preference uint `xml:"preference,attr"`
}

type sDB struct {
	XMLName        xml.Name          `xml:"AS4200240XXX"`
	AB             []sDB_AB          `xml:"Security>AB_List>AB"`
	Application    []sDB_Application `xml:"Security>Application_List>Application"`
	Peer           []sDB_Peer        `xml:"Peer_List>Peer"`
	VI             []sDB_VI          `xml:"VI_List>VI"`
	Domain_Name    _FQDN             `xml:"domain_name,attr"`
	VI_IPPrefix    netip.Prefix      `xml:"VI_IPprefix,attr"`
	GT_List        string            `xml:"GT_list,attr"`
	Upload_Path    string            `xml:"upload_path,attr"`
	Templates_Path string            `xml:"templates_path,attr"`
	Verbosity      string            `xml:"verbosity,attr"`
	_service_attributes
}
type sDB_Peer struct {
	ASN             _ASN                        `xml:"ASN,attr"`
	IFM             []sDB_Peer_IFM              `xml:"IFM"`
	RI              []sDB_Peer_RI               `xml:"RI"`
	Hostname        _FQDN                       `xml:"hostname,attr"`
	Domain_Name     _FQDN                       `xml:"domain_name,attr"`
	Version         string                      `xml:"version,attr"`
	Manufacturer    string                      `xml:"manufacturer,attr"`
	Model           string                      `xml:"model,attr"`
	Serial          string                      `xml:"serial,attr"`
	Root            _Secret                     `xml:"root,attr"`
	GT_List         string                      `xml:"GT_list,attr"`
	SZ              []sDB_Peer_Security_Zone_SZ `xml:"Security>Zone>SZ"`
	NAT_Source      []_Security_NAT_Source      `xml:"Security>NAT>Source"`
	NAT_Destination []_Security_NAT_Destination `xml:"Security>NAT>Destination"`
	NAT_Static      []_Security_NAT_Static      `xml:"Security>NAT>Static"`
	Policies_Exact  []_Security_Policies_Exact  `xml:"Security>Policies>Exact"`
	Policies_Global []_Security_Policies_Policy `xml:"Security>Policies>Global"`
	AB              []sDB_AB                    `xml:"Security>AB"`
	Application     []sDB_Application           `xml:"Security>Application"`
	_service_attributes
}
type sDB_AB struct {
	Name    _AB_Name         `xml:"name,attr"`
	Set     bool             `xml:"set,attr"`
	Address []sDB_AB_Address `xml:"Address"`
	_service_attributes
}
type sDB_AB_Address struct {
	AB       _AB_Name     `xml:"AB,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	FQDN     _FQDN        `xml:"FQDN,attr"`
	_service_attributes
}
type sDB_Application struct {
	Name _Application_Name            `xml:"name,attr"`
	Term []_Security_Application_Term `xml:"Term"`
	_service_attributes
}
type sDB_Peer_Security_Zone_SZ struct {
	Name   _SZ_Name     `xml:"name,attr"`
	Screen _Screen_Name `xml:"screen,attr"`
	_service_attributes
}

type sDB_Peer_IFM struct {
	Name          _IFM_Name         `xml:"name,attr"`
	Communication _IF_Communication `xml:"communication,attr"`
	Disable       bool              `xml:"disable,attr"`
	_service_attributes
}
type sDB_Peer_RI struct {
	Name _RI_Name         `xml:"name,attr"`
	RT   []sDB_Peer_RI_RT `xml:"RT"`
	IF   []sDB_Peer_RI_IF `xml:"IF"`
	_service_attributes
}
type sDB_Peer_RI_IF struct {
	Name          _IF_Name              `xml:"name,attr"`
	Communication _IF_Communication     `xml:"communication,attr"`
	IP            []sDB_Peer_RI_IF_IP   `xml:"IP"`
	PARP          []sDB_Peer_RI_IF_PARP `xml:"PARP"`
	Disable       bool                  `xml:"disable,attr"`
	_service_attributes
}
type sDB_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix `xml:"IPprefix,attr"`
	Router_ID bool         `xml:"router_ID,attr"`
	Primary   bool         `xml:"primary,attr"`
	Preferred bool         `xml:"preferred,attr"`
	NAT       netip.Addr   `xml:"NAT,attr"`
	DHCP      bool         `xml:"DHCP,attr"`
	_service_attributes
}
type sDB_Peer_RI_IF_PARP struct {
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	NAT      netip.Addr   `xml:"NAT,attr"`
	_service_attributes
}
type sDB_Peer_RI_RT struct {
	Identifier netip.Prefix        `xml:"identifier,attr"`
	GW         []sDB_Peer_RI_RT_GW `xml:"GW"`
	_service_attributes
}
type sDB_Peer_RI_RT_GW struct {
	IP      netip.Addr `xml:"IP,attr"`
	IF      _IF_Name   `xml:"IF,attr"`
	Table   string     `xml:"table,attr"`
	Discard bool       `xml:"discard,attr"`
	Type    _GW_Type   `xml:"type,attr"`
	_Route_Attributes
	_service_attributes
}
type sDB_VI struct {
	ID            _VI_ID            `xml:"index,attr"`
	Type          _VI_Type          `xml:"type,attr"`
	Communication _IF_Communication `xml:"communication,attr"`
	Route_Metric  uint              `xml:"route_metric,attr"`
	Peer          []sDB_VI_Peer     `xml:"Peer"`
	PSK           _Secret           `xml:"PSK,attr"`
	_service_attributes
}
type sDB_VI_Peer struct {
	ID       _VI_Peer_ID `xml:"index,attr"`
	ASN      _ASN        `xml:"ASN,attr"`
	RI       _RI_Name    `xml:"RI,attr"`
	IF       _IF_Name    `xml:"IF,attr"`
	IP       netip.Addr  `xml:"IP,attr"`
	Dynamic  bool        `xml:"dynamic,attr"`
	Hub      bool        `xml:"hub,attr"`
	Inner_RI _RI_Name    `xml:"inner_RI,attr"`
	_service_attributes
}

type pDB_Peer struct {
	ASN             _ASN
	ASN_PName       _ASN_PName
	Router_ID       netip.Addr
	AB              map[_AB_Name]_Security_AB
	Application     map[_Application_Name][]_Security_Application_Term
	SZ              map[_SZ_Name]pDB_Peer_Security_Zone_SZ
	NAT_Source      []_Security_NAT_Source
	NAT_Destination []_Security_NAT_Destination
	NAT_Static      []_Security_NAT_Static
	Policies_Exact  []_Security_Policies_Exact
	Policies_Global []_Security_Policies_Policy
	IFM             map[_IFM_Name]pDB_Peer_IFM
	RI              map[_RI_Name]pDB_Peer_RI
	IF_RI           map[_IF_Name]_RI_Name
	Hostname        _FQDN
	Domain_Name     _FQDN
	Version         string
	Major           float64
	IKE_GCM         bool
	Manufacturer    string
	Model           string
	Serial          string
	Root            _Secret
	GT_List         []_GT_Name
	VI              map[_VI_ID]pDB_Peer_VI
	RM_ID           *_RM_ID
	IPPrefix_List   map[netip.Prefix]bool // true = public
	_service_attributes
}
type pDB_Peer_Security_Zone_SZ struct {
	Screen _Screen_Name
	IF     map[_IF_Name]pDB_Peer_Security_Zone_SZ_IF
	_Host_Inbound_Traffic
	_service_attributes
}
type pDB_Peer_Security_Zone_SZ_IF struct {
	_Host_Inbound_Traffic
	_service_attributes
}
type pDB_Peer_RI struct {
	RT    map[netip.Prefix]pDB_Peer_RI_RT
	IF    map[_IF_Name]pDB_Peer_RI_IF
	IP_IF map[netip.Addr]_IF_Name
	_service_attributes
}
type pDB_Peer_RI_RT struct {
	GW map[_GW_Name]pDB_Peer_RI_RT_GW
	_service_attributes
}
type pDB_Peer_RI_RT_GW struct {
	IP      netip.Addr // name candidate priority 1
	IF      _IF_Name   // name candidate priority 2
	Table   string     // name candidate priority 3
	Discard bool       // name candidate priority 0
	Type    _GW_Type   // fill type appropriately
	_Route_Attributes
	_service_attributes
}
type pDB_Peer_IFM struct {
	Communication _IF_Communication
	Disable       bool
	_service_attributes
}
type pDB_Peer_RI_IF struct {
	Communication _IF_Communication
	Major         string
	Minor         string
	IP            map[netip.Addr]pDB_Peer_RI_IF_IP
	PARP          map[netip.Addr]pDB_Peer_RI_IF_PARP
	Disable       bool
	_service_attributes
}
type pDB_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix
	Masked    netip.Prefix
	Router_ID bool
	Primary   bool
	Preferred bool
	NAT       netip.Addr
	DHCP      bool
	_service_attributes
}
type pDB_Peer_RI_IF_PARP struct {
	IPPrefix netip.Prefix
	NAT      netip.Addr
	_service_attributes
}
type pDB_Peer_VI struct {
	VI_ID_PName          _VI_ID_PName
	Type                 _VI_Type
	Communication        _IF_Communication
	PSK                  _Secret
	Route_Metric         uint
	IPPrefix             netip.Prefix
	No_NAT               bool
	IKE_GCM              bool
	Left_ASN             _ASN
	Left_RI              _RI_Name
	Left_IF              _IF_Name
	Left_IP              netip.Addr
	Left_NAT             netip.Addr
	Left_Local_Address   bool
	Left_Dynamic         bool
	Left_Hub             bool
	Left_Inner_RI        _RI_Name
	Left_Inner_IP        netip.Addr
	Left_Inner_IPPrefix  netip.Prefix
	Right_ASN            _ASN
	Right_RI             _RI_Name
	Right_IF             _IF_Name
	Right_IP             netip.Addr
	Right_NAT            netip.Addr
	Right_Local_Address  bool
	Right_Dynamic        bool
	Right_Hub            bool
	Right_Inner_RI       _RI_Name
	Right_Inner_IP       netip.Addr
	Right_Inner_IPPrefix netip.Prefix
	_service_attributes
}
type pDB_GT struct {
	Content _GT_Content
	_service_attributes
}

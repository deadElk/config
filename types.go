package main

import (
	"encoding/xml"
	"net/netip"
)

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.
// type _AB map[_AB_Name]_AB2
type _AB_Type string
type _AB struct {
	Type     _AB_Type
	AB       []_AB_Name
	FQDN     []_FQDN
	IPPrefix []netip.Prefix
}
type _AB_Name string
type _Application map[_Application_Name]string
type _Application_Name string
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

type Host_Inbound_Traffic struct {
	Services  map[_Service]bool  `xml:"service,attr"`
	Protocols map[_Protocol]bool `xml:"protocol,attr"`
}
type Route_Attributes struct {
	QNH        bool `xml:"QNH,attr"`
	Metric     uint `xml:"metric,attr"`
	Preference uint `xml:"preference,attr"`
}

// type _Service_List map[_Service]bool
// type _Protocol_List map[_Protocol]bool
// type _Services struct {
// 	All               bool
// 	Any_Service       bool
// 	appqoe            bool
// 	BOOTP             bool
// 	DHCP              bool
// 	DHCPv6            bool
// 	dns               bool
// 	finger            bool
// 	ftp               bool
// 	http              bool
// 	https             bool
// 	ident_reset       bool
// 	IKE               bool
// 	lsping            bool
// 	netconf           bool
// 	ntp               bool
// 	PING              bool
// 	r2cp              bool
// 	reverse_ssh       bool
// 	reverse_telnet    bool
// 	rlogin            bool
// 	rpm               bool
// 	rsh               bool
// 	SNMP              bool
// 	SNMP_Trap         bool
// 	SSH               bool
// 	tcp_encap         bool
// 	telnet            bool
// 	tftp              bool
// 	Traceroute        bool
// 	webapi_clear_text bool
// 	webapi_ssl        bool
// 	xnm_clear_text    bool
// 	xnm_ssl           bool
// }
// type _Protocols struct {
// 	All              bool
// 	bfd              bool
// 	BGP              bool
// 	dvmrp            bool
// 	igmp             bool
// 	ldp              bool
// 	msdp             bool
// 	nhrp             bool
// 	ospf             bool
// 	ospf3            bool
// 	pgm              bool
// 	pim              bool
// 	rip              bool
// 	ripng            bool
// 	router_discovery bool
// 	rsvp             bool
// 	sap              bool
// 	vrrp             bool
// }

type _service_attributes struct {
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
	// Verbosity   string       `xml:"verbosity,attr"`
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
	ASN          _ASN                `xml:"ASN,attr"`
	IFM          []sDB_Peer_IFM      `xml:"IFM"`
	RI           []sDB_Peer_RI       `xml:"RI"`
	Hostname     _FQDN               `xml:"hostname,attr"`
	Domain_Name  _FQDN               `xml:"domain_name,attr"`
	Version      string              `xml:"version,attr"`
	Manufacturer string              `xml:"manufacturer,attr"`
	Model        string              `xml:"model,attr"`
	Serial       string              `xml:"serial,attr"`
	Root         _Secret             `xml:"root,attr"`
	GT_List      string              `xml:"GT_list,attr"`
	Secutiry     []sDB_Peer_Security `xml:"Security"`
	_service_attributes
}
type sDB_Peer_Security struct {
	Zone        []sDB_Peer_Security_Zone     `xml:"Zone"`
	NAT         []sDB_Peer_Security_NAT      `xml:"NAT"`
	Policies    []sDB_Peer_Security_Policies `xml:"Policies"`
	AB          []sDB_AB                     `xml:"AB"`
	Application []sDB_Application            `xml:"Application"`
	_service_attributes
}
type sDB_AB struct {
	Name    _AB_Name         `xml:"name,attr"`
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
	Name _Application_Name      `xml:"name,attr"`
	Term []sDB_Application_Term `xml:"Term"`
	_service_attributes
}
type sDB_Application_Term struct {
	Name             string `xml:"name,attr"`
	Protocol         string `xml:"protocol,attr"`
	Destination_Port uint16 `xml:"destination_port,attr"`
	_service_attributes
}
type sDB_Peer_Security_Zone struct {
	SZ []sDB_Peer_Security_Zone_SZ `xml:"SZ"`
	_service_attributes
}
type sDB_Peer_Security_Zone_SZ struct {
	Name   _SZ_Name     `xml:"name,attr"`
	Screen _Screen_Name `xml:"screen,attr"`
	_service_attributes
}
type sDB_Peer_Security_NAT struct {
	Source      []sDB_Peer_Security_NAT_Source      `xml:"Source"`
	Destination []sDB_Peer_Security_NAT_Destination `xml:"Destination"`
	Static      []sDB_Peer_Security_NAT_Static      `xml:"Static"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Source struct {
	Address_Persistent bool                             `xml:"address_persistent,attr"`
	Pool               []sDB_Peer_Security_NAT_Pool     `xml:"Pool"`
	Rule_Set           []sDB_Peer_Security_NAT_Rule_Set `xml:"Rule_Set"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Destination struct {
	Pool     []sDB_Peer_Security_NAT_Pool     `xml:"Pool"`
	Rule_Set []sDB_Peer_Security_NAT_Rule_Set `xml:"Rule_Set"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Static struct {
	_service_attributes
}
type sDB_Peer_Security_NAT_Pool struct {
	Name     _Pool_Name   `xml:"name,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	RI       _RI_Name     `xml:"RI,attr"`
	SZ       _SZ_Name     `xml:"SZ,attr"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Rule_Set struct {
	Name _Rule_Set_Name                    `xml:"name,attr"`
	From []sDB_Peer_Security_NAT_Direction `xml:"From"`
	To   []sDB_Peer_Security_NAT_Direction `xml:"To"`
	Rule []sDB_Peer_Security_NAT_Rule      `xml:"Rule"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Direction struct {
	SZ _SZ_Name `xml:"SZ,attr"`
	RI _RI_Name `xml:"RI,attr"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Rule struct {
	Name  _Rule_Name                         `xml:"name,attr"`
	Match []sDB_Peer_Security_NAT_Rule_Match `xml:"Match"`
	Then  []sDB_Peer_Security_NAT_Rule_Then  `xml:"Then"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Rule_Match struct {
	Source      bool              `xml:"source,attr"`
	Destination bool              `xml:"destination,attr"`
	Application _Application_Name `xml:"application,attr"`
	AB          _AB_Name          `xml:"AB,attr"`
	_service_attributes
}
type sDB_Peer_Security_NAT_Rule_Then struct {
	Source_NAT      bool       `xml:"source_NAT,attr"`
	Destination_NAT bool       `xml:"destination_NAT,attr"`
	Pool            _Pool_Name `xml:"pool,attr"`
	Permit          bool       `xml:"permit,attr"`
	Deny            bool       `xml:"deny,attr"`
	_service_attributes
}
type sDB_Peer_Security_Policies struct {
	From_To []string `xml:"From_To"`
	Global  []string `xml:"Global"`
	_service_attributes
}

type sDB_Peer_IFM struct {
	Name          _IFM_Name         `xml:"name,attr"`
	Communication _IF_Communication `xml:"communication,attr"`
	Disable       bool              `xml:"disable,attr"`
	_service_attributes
}
type sDB_Peer_RI struct {
	Name   _RI_Name         `xml:"name,attr"`
	RT     []sDB_Peer_RI_RT `xml:"RT"`
	IF     []sDB_Peer_RI_IF `xml:"IF"`
	Policy _Policy          `xml:"policy,attr"`
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
	Route_Attributes
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
	ASN           _ASN
	ASN_PName     _ASN_PName
	Router_ID     netip.Addr
	IFM           map[_IFM_Name]pDB_Peer_IFM
	RI            map[_RI_Name]pDB_Peer_RI
	IF_RI         map[_IF_Name]_RI_Name
	Hostname      _FQDN
	Domain_Name   _FQDN
	Version       string
	Major         float64
	IKE_GCM       bool
	Manufacturer  string
	Model         string
	Serial        string
	GT_Patch      _GT_Content
	Root          _Secret
	GT_List       []_GT_Name
	VI            map[_VI_ID]pDB_Peer_VI
	RM_ID         *_RM_ID
	AB            *_AB
	IPPrefix_List map[netip.Prefix]bool // true = public
	_service_attributes
}
type pDB_Peer_RI struct {
	RT     map[netip.Prefix]pDB_Peer_RI_RT
	IF     map[_IF_Name]pDB_Peer_RI_IF
	IP_IF  map[netip.Addr]_IF_Name
	Policy _Policy
	Host_Inbound_Traffic
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
	Route_Attributes
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
	Host_Inbound_Traffic
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

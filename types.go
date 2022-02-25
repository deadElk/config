package main

import (
	"encoding/xml"
	"net/netip"
)

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.

// Why return String() "invalid ID"???? What for???? Why not just return an empty String() "" ????
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
type _Route_Attributes struct {
	Action     _Action `xml:"action,attr"`
	Metric     uint    `xml:"metric,attr"`
	Preference uint    `xml:"preference,attr"`
}

type _ASN uint32
type _Action string
type _Communication string
type _Default string
type _Description string
type _FQDN string
type _Content string
type _Mask string
type _Mode string
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

type _Security_AB struct {
	Address   interface{}
	Type      _Type
	Addresses map[_Name]_Type
	_Service_Attributes
}
type _Security_Application_Term struct {
	Name             _Name     `xml:"name,attr"`
	Protocol         _Protocol `xml:"protocol,attr"`
	Destination_Port uint16    `xml:"destination_port,attr"`
	_Service_Attributes
}
type _Security_NAT_List struct {
	Source      []_Security_NAT `xml:"Source"`
	Destination []_Security_NAT `xml:"Destination"`
	Static      []_Security_NAT `xml:"Static"`
}
type _Security_NAT struct {
	Address_Persistent bool                 `xml:"address_persistent,attr"`
	Pool               []_Security_Pool     `xml:"Pool"`
	Rule_Set           []_Security_Rule_Set `xml:"Rule_Set"`
	_Service_Attributes
}
type _Security_Pool struct {
	Name     _Name        `xml:"name,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	RI       _Name        `xml:"RI,attr"`
	SZ       _Name        `xml:"SZ,attr"`
	_Service_Attributes
}
type _Security_Rule_Set struct {
	Name _Name                 `xml:"name,attr"`
	From []_Security_Direction `xml:"From"`
	To   []_Security_Direction `xml:"To"`
	Rule []_Security_Rule      `xml:"Rule"`
	_Service_Attributes
}
type _Security_Direction struct {
	IF _Name `xml:"IF,attr"`
	SZ _Name `xml:"SZ,attr"`
	RI _Name `xml:"RI,attr"`
	RG _Name `xml:"RG,attr"`
	_Service_Attributes
}
type _Security_Rule struct {
	Name  _Name             `xml:"name,attr"`
	Match []_Security_Match `xml:"Match"`
	Then  []_Security_Then  `xml:"Then"`
	_Service_Attributes
}
type _Security_Match struct {
	Source_AB             _Name  `xml:"source_AB,attr"`
	Destination_AB        _Name  `xml:"destination_AB,attr"`
	Application           _Name  `xml:"application,attr"`
	From_SZ               _Name  `xml:"from_SZ,attr"`
	To_SZ                 _Name  `xml:"to_SZ,attr"`
	From_RI               _Name  `xml:"from_RI,attr"`
	To_RI                 _Name  `xml:"to_RI,attr"`
	Source_Port_Low       uint16 `xml:"source_port_low,attr"`
	Source_Port_High      uint16 `xml:"source_port_high,attr"`
	Destination_Port_Low  uint16 `xml:"destination_port_low,attr"`
	Destination_Port_High uint16 `xml:"destination_port_high,attr"`
	_Service_Attributes
}
type _Security_Then struct {
	Action           _Action `xml:"action,attr"`
	Pool             _Name   `xml:"pool,attr"`
	AB               _Name   `xml:"AB,attr"`
	RI               _Name   `xml:"RI,attr"`
	Mapped_Port_Low  uint16  `xml:"mapped_port_low,attr"`
	Mapped_Port_High uint16  `xml:"mapped_port_high,attr"`
	_Service_Attributes
}
type _Security_SP struct {
	SP_Default _Action              `xml:"default_policy,attr"`
	SP_Exact   []_Security_Rule_Set `xml:"Exact"`
	SP_Global  []_Security_Rule     `xml:"Global"`
	_Service_Attributes
}

type sDB_PO_PL struct {
	Name     _Name        `xml:"name,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	_Service_Attributes
}
type _PO_PS struct {
	Name _Name       `xml:"name,attr"`
	Term _PO_PS_Term `xml:"Term"`
	_Service_Attributes
}
type _PO_PS_Term struct {
	Name _Name         `xml:"name,attr"`
	From []_PO_PS_From `xml:"From,attr"`
	Then []_PO_PS_Then `xml:"Then,attr"`
	_Service_Attributes
}
type _PO_PS_From struct {
	Protocol _Protocol `xml:"protocol,attr"`
	PO_PL    _Name     `xml:"prefix-list-filter,attr"`
	Measure  _Mask     `xml:"measure,attr"`
	_Service_Attributes
}
type _PO_PS_Then struct {
	Action _Action `xml:"action,attr"`
	_Service_Attributes
}
type _PO struct {
	PL map[_Name]map[netip.Prefix]bool
	PS map[_Name][]_PO_PS_Term
}
type sDB struct {
	XMLName     xml.Name          `xml:"AS4200240XXX"`
	AB          []sDB_AB          `xml:"Vocabulary>AB_List>AB"`
	Application []sDB_Application `xml:"Vocabulary>Application_List>Application"`
	PL          []sDB_PO_PL       `xml:"Vocabulary>PO>PL"`
	PS          []_PO_PS          `xml:"Vocabulary>PO>PS"`
	Peer        []sDB_Peer        `xml:"Peer_List>Peer"`
	VI          []sDB_VI          `xml:"VI_List>VI"`
	Domain_Name _FQDN             `xml:"domain_name,attr"`
	VI_IPPrefix netip.Prefix      `xml:"VI_IPprefix,attr"`
	GT_List     string            `xml:"GT_list,attr"`
	Upload_Path string            `xml:"upload_path,attr"`
	GT_Path     string            `xml:"GT_path,attr"`
	_Service_Attributes
}
type sDB_Peer struct {
	ASN          _ASN                        `xml:"ASN,attr"`
	IFM          []sDB_Peer_IFM              `xml:"IFM"`
	RI           []sDB_Peer_RI               `xml:"RI"`
	Hostname     _FQDN                       `xml:"hostname,attr"`
	Domain_Name  _FQDN                       `xml:"domain_name,attr"`
	Version      string                      `xml:"version,attr"`
	Manufacturer string                      `xml:"manufacturer,attr"`
	Model        string                      `xml:"model,attr"`
	Serial       string                      `xml:"serial,attr"`
	Root         _Secret                     `xml:"root,attr"`
	GT_List      string                      `xml:"GT_list,attr"`
	AB           []sDB_AB                    `xml:"Vocabulary>AB"`
	Application  []sDB_Application           `xml:"Vocabulary>Application"`
	SZ           []sDB_Peer_Security_Zone_SZ `xml:"Security>Zone>SZ"`
	NAT          _Security_NAT_List          `xml:"Security>NAT"`
	SP           _Security_SP                `xml:"Security>SP"`
	_Service_Attributes
}
type sDB_AB struct {
	Name    _Name            `xml:"name,attr"`
	Set     bool             `xml:"set,attr"`
	Address []sDB_AB_Address `xml:"Address"`
	_Service_Attributes
}
type sDB_AB_Address struct {
	AB       _Name        `xml:"AB,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	FQDN     _FQDN        `xml:"FQDN,attr"`
	_Service_Attributes
}
type sDB_Application struct {
	Name _Name                        `xml:"name,attr"`
	Term []_Security_Application_Term `xml:"Term"`
	_Service_Attributes
}
type sDB_Peer_Security_Zone_SZ struct {
	Name   _Name `xml:"name,attr"`
	Screen _Name `xml:"screen,attr"`
	_Service_Attributes
}

type sDB_Peer_IFM struct {
	Name          _Name          `xml:"name,attr"`
	Communication _Communication `xml:"communication,attr"`
	Disable       bool           `xml:"disable,attr"`
	_Service_Attributes
}
type sDB_Peer_RI struct {
	Name            _Name              `xml:"name,attr"`
	RT              []sDB_Peer_RI_RT   `xml:"RT"`
	IF              []sDB_Peer_RI_IF   `xml:"IF"`
	Routing_Options []_Routing_Options `xml:"Routing_Options"`
	_Service_Attributes
}
type _Routing_Options struct {
	Import _Name `xml:"import,attr"`
	Export _Name `xml:"export,attr"`
	_Service_Attributes
}
type sDB_Peer_RI_IF struct {
	Name          _Name                 `xml:"name,attr"`
	Communication _Communication        `xml:"communication,attr"`
	IP            []sDB_Peer_RI_IF_IP   `xml:"IP"`
	PARP          []sDB_Peer_RI_IF_PARP `xml:"PARP"`
	Disable       bool                  `xml:"disable,attr"`
	_Service_Attributes
}
type sDB_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix `xml:"IPprefix,attr"`
	Router_ID bool         `xml:"router_ID,attr"`
	Primary   bool         `xml:"primary,attr"`
	Preferred bool         `xml:"preferred,attr"`
	NAT       netip.Addr   `xml:"NAT,attr"`
	DHCP      bool         `xml:"DHCP,attr"`
	_Service_Attributes
}
type sDB_Peer_RI_IF_PARP struct {
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	NAT      netip.Addr   `xml:"NAT,attr"`
	_Service_Attributes
}
type sDB_Peer_RI_RT struct {
	Identifier netip.Prefix        `xml:"identifier,attr"`
	GW         []sDB_Peer_RI_RT_GW `xml:"GW"`
	_Service_Attributes
}
type sDB_Peer_RI_RT_GW struct {
	IP     netip.Addr `xml:"IP,attr"`
	IF     _Name      `xml:"IF,attr"`
	Table  _Name      `xml:"table,attr"`
	Action _Action    `xml:"action,attr"`
	_Route_Attributes
	_Service_Attributes
}
type sDB_VI struct {
	ID            _VI_ID         `xml:"index,attr"`
	Type          _Type          `xml:"type,attr"`
	Communication _Communication `xml:"communication,attr"`
	Route_Metric  uint32         `xml:"route_metric,attr"`
	Peer          []sDB_VI_Peer  `xml:"Peer"`
	PSK           _Secret        `xml:"PSK,attr"`
	_Service_Attributes
}
type sDB_VI_Peer struct {
	ID       _VI_Peer_ID `xml:"index,attr"`
	ASN      _ASN        `xml:"ASN,attr"`
	RI       _Name       `xml:"RI,attr"`
	IF       _Name       `xml:"IF,attr"`
	IP       netip.Addr  `xml:"IP,attr"`
	Dynamic  bool        `xml:"dynamic,attr"`
	Inner_RI _Name       `xml:"inner_RI,attr"`
	_Service_Attributes
}

type pDB_Peer struct {
	ASN         _ASN
	ASN_PName   _PName
	Router_ID   netip.Addr
	AB          map[_Name]_Security_AB
	Application map[_Name][]_Security_Application_Term
	SZ          map[_Name]pDB_Peer_Security_Zone_SZ
	_Security_NAT_List
	_Security_SP
	_PO
	IFM           map[_Name]pDB_Peer_IFM
	RI            map[_Name]pDB_Peer_RI
	IF_RI         map[_Name]_Name
	Hostname      _FQDN
	Domain_Name   _FQDN
	Version       string
	Major         float64
	IKE_GCM       bool
	Manufacturer  string
	Model         string
	Serial        string
	Root          _Secret
	GT_List       []_Name
	VI            map[_VI_ID]pDB_Peer_VI
	IPPrefix_List map[netip.Prefix]bool // true = public
	_Service_Attributes
}
type pDB_Peer_Security_Zone_SZ struct {
	Screen _Name
	IF     map[_Name]pDB_Peer_Security_Zone_SZ_IF
	_Host_Inbound_Traffic
	_Service_Attributes
}
type pDB_Peer_Security_Zone_SZ_IF struct {
	_Host_Inbound_Traffic
	_Service_Attributes
}
type pDB_Peer_RI struct {
	RT    map[netip.Prefix]pDB_Peer_RI_RT
	IF    map[_Name]pDB_Peer_RI_IF
	IP_IF map[netip.Addr]_Name
	_Service_Attributes
}
type pDB_Peer_RI_RT struct {
	GW map[_Name]pDB_Peer_RI_RT_GW
	_Service_Attributes
}
type pDB_Peer_RI_RT_GW struct {
	IP     netip.Addr // name candidate priority 1
	IF     _Name      // name candidate priority 2
	Table  _Name      // name candidate priority 3
	Action _Action    // fill action appropriately
	_Route_Attributes
	_Service_Attributes
}
type pDB_Peer_IFM struct {
	Communication _Communication
	Disable       bool
	_Service_Attributes
}
type pDB_Peer_RI_IF struct {
	Communication _Communication
	IFM           _Name
	IFsM          _Name
	IP            map[netip.Addr]pDB_Peer_RI_IF_IP
	PARP          map[netip.Addr]pDB_Peer_RI_IF_PARP
	Disable       bool
	_Service_Attributes
}
type pDB_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix
	Masked    netip.Prefix
	Router_ID bool
	Primary   bool
	Preferred bool
	NAT       netip.Addr
	DHCP      bool
	_Service_Attributes
}
type pDB_Peer_RI_IF_PARP struct {
	IPPrefix netip.Prefix
	NAT      netip.Addr
	_Service_Attributes
}
type pDB_Peer_VI struct {
	VI_ID_PName          _PName
	Type                 _Type
	Communication        _Communication
	PSK                  _Secret
	Route_Metric         uint32
	IPPrefix             netip.Prefix
	No_NAT               bool
	IKE_GCM              bool
	Left_ASN             _ASN
	Left_RI              _Name
	Left_IF              _Name
	Left_IP              netip.Addr
	Left_NAT             netip.Addr
	Left_Local_Address   bool
	Left_Dynamic         bool
	Left_Hub             bool
	Left_Inner_RI        _Name
	Left_Inner_IP        netip.Addr
	Left_Inner_IPPrefix  netip.Prefix
	Right_ASN            _ASN
	Right_RI             _Name
	Right_IF             _Name
	Right_IP             netip.Addr
	Right_NAT            netip.Addr
	Right_Local_Address  bool
	Right_Dynamic        bool
	Right_Hub            bool
	Right_Inner_RI       _Name
	Right_Inner_IP       netip.Addr
	Right_Inner_IPPrefix netip.Prefix
	_Service_Attributes
}
type pDB_GT struct {
	Content _Content
	_Service_Attributes
}

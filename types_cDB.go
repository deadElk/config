package main

import (
	"encoding/xml"
	"net/netip"
)

// DB root
type cDB struct {
	XMLName     xml.Name
	Domain_Name _FQDN        `xml:"domain_name,attr"`
	VI_IPPrefix netip.Prefix `xml:"VI_IPprefix,attr"`
	GT_List     string       `xml:"GT_list,attr"`
	Upload_Path string       `xml:"upload_path,attr"`
	GT_Path     string       `xml:"GT_path,attr"`
	Peer        []*cDB_Peer  `xml:"Peer_List>Peer"`
	VI          []*cDB_VI    `xml:"VI_List>VI"`
	cDB_Vocabulary
	_Attribute_List
}

// Vocabulary
type cDB_Vocabulary struct {
	AB []*cDB_AB    `xml:"Vocabulary>AB_List>AB"`
	JA []*cDB_JA    `xml:"Vocabulary>Application_List>Application"`
	PL []*cDB_PO_PL `xml:"Vocabulary>PO>PL"`
	PS []*cDB_PO_PS `xml:"Vocabulary>PO>PS"`
	_Attribute_List
}

// Peer
type cDB_Peer struct {
	ASN             _ASN               `xml:"ASN,attr"`
	Router_ID       netip.Addr         `xml:"router_ID,attr"`
	IFM             []cDB_Peer_IFM     `xml:"IFM"`
	RI              []cDB_Peer_RI      `xml:"RI"`
	Hostname        _FQDN              `xml:"hostname,attr"`
	Domain_Name     _FQDN              `xml:"domain_name,attr"`
	Version         string             `xml:"version,attr"`
	Manufacturer    string             `xml:"manufacturer,attr"`
	Model           string             `xml:"model,attr"`
	Serial          string             `xml:"serial,attr"`
	Root            _Secret            `xml:"root,attr"`
	GT_List         string             `xml:"GT_list,attr"`
	SZ              []cDB_SZ           `xml:"Security>Zone>SZ"`
	NAT_Source      cDB_NAT            `xml:"Security>NAT>Source"`
	NAT_Destination cDB_NAT            `xml:"Security>NAT>Destination"`
	NAT_Static      cDB_NAT            `xml:"Security>NAT>Static"`
	SP_Option_List  cDB_SP_Option_List `xml:"Security>SP>Option_List"`
	SP_Exact        []cDB_Rule_Set     `xml:"Security>SP>Exact"`
	SP_Global       []cDB_Rule         `xml:"Security>SP>Global"`
	FW              []cDB_FW           `xml:"Security>FW_List>FW"`
	cDB_Vocabulary
	// cDB_Security
	_Attribute_List
}
type cDB_FW struct {
	Name _Name         `xml:"name,attr"`
	Term []cDB_FW_Term `xml:"Term"`
	_Attribute_List
}
type cDB_FW_Term struct {
	Name _Name           `xml:"name,attr"`
	From []cDB_FW_FromTo `xml:"From"`
	To   []cDB_FW_FromTo `xml:"To"`
	Then []cDB_FW_Then   `xml:"Then"`
	_Attribute_List
}
type cDB_FW_FromTo struct {
	PL _Name `xml:"PL,attr"`
	_Attribute_List
}
type cDB_FW_Then struct {
	Action      _Action `xml:"action,attr"`
	Action_Flag _Action `xml:"action_flag,attr"`
	RI          _Name   `xml:"RI,attr"`
	_Attribute_List
}

type cDB_Peer_IFM struct {
	Name          _Name          `xml:"name,attr"`
	Communication _Communication `xml:"communication,attr"`
	_Attribute_List
}
type cDB_Peer_RI struct {
	Name       _Name                     `xml:"name,attr"`
	IF         []cDB_Peer_RI_IF          `xml:"IF"`
	RT         []cDB_Peer_RI_RO_RT       `xml:"RO>RT"`
	Route_Leak cDB_Peer_RI_RO_Route_Leak `xml:"RO>Route_Leak"`
	_Attribute_List
}
type cDB_Peer_RI_RO_Route_Leak struct {
	Import []cDB_Peer_RI_RO_Route_Leak_FromTo `xml:"Import"`
	Export []cDB_Peer_RI_RO_Route_Leak_FromTo `xml:"Export"`
	_Attribute_List
}
type cDB_Peer_RI_IF struct {
	Name          _Name                 `xml:"name,attr"`
	Communication _Communication        `xml:"communication,attr"`
	IP            []cDB_Peer_RI_IF_IP   `xml:"IP"`
	PARP          []cDB_Peer_RI_IF_PARP `xml:"PARP"`
	_Attribute_List
}
type cDB_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix `xml:"IPprefix,attr"`
	Router_ID bool         `xml:"router_ID,attr"`
	Primary   bool         `xml:"primary,attr"`
	Preferred bool         `xml:"preferred,attr"`
	NAT       netip.Addr   `xml:"NAT,attr"`
	DHCP      bool         `xml:"DHCP,attr"`
	_Attribute_List
}
type cDB_Peer_RI_IF_PARP struct {
	IP  netip.Addr `xml:"IP,attr"`
	NAT netip.Addr `xml:"NAT,attr"`
	_Attribute_List
}
type cDB_Peer_RI_RO_RT struct {
	Identifier netip.Prefix           `xml:"identifier,attr"`
	GW         []cDB_Peer_RI_RO_RT_GW `xml:"GW"`
	_Attribute_List
}
type cDB_Peer_RI_RO_RT_GW struct {
	IP          netip.Addr    `xml:"IP,attr"`
	IF          _Name         `xml:"IF,attr"`
	Table       _Name         `xml:"table,attr"`
	Action      _Action       `xml:"action,attr"`
	Action_Flag _Action       `xml:"action_flag,attr"`
	Metric      _Route_Weight `xml:"metric,attr"`
	Preference  _Route_Weight `xml:"preference,attr"`
	_Attribute_List
}
type cDB_Peer_RI_RO_Route_Leak_FromTo struct {
	PS _Name `xml:"PS,attr"`
	_Attribute_List
}

// Virtual Interfaces
type cDB_VI struct {
	ID            _VI_ID         `xml:"ID,attr"`
	Type          _Type          `xml:"type,attr"`
	Communication _Communication `xml:"communication,attr"`
	Route_Metric  _Route_Weight  `xml:"route_metric,attr"`
	Peer          []cDB_VI_Peer  `xml:"Peer"`
	PSK           _Secret        `xml:"PSK,attr"`
	_Attribute_List
}
type cDB_VI_Peer struct {
	ID         _VI_Peer_ID               `xml:"ID,attr"`
	ASN        _ASN                      `xml:"ASN,attr"`
	RI         _Name                     `xml:"RI,attr"`
	IF         _Name                     `xml:"IF,attr"`
	IP         netip.Addr                `xml:"IP,attr"`
	Hub        bool                      `xml:"hub,attr"`
	Inner_RI   _Name                     `xml:"inner_RI,attr"`
	Route_Leak cDB_Peer_RI_RO_Route_Leak `xml:"Route_Leak"`
	_Attribute_List
}

// Security
type cDB_SZ struct {
	Name   _Name `xml:"name,attr"`
	Screen _Name `xml:"screen,attr"`
	_Attribute_List
}
type cDB_NAT struct {
	Address_Persistent bool           `xml:"address_persistent,attr"`
	Pool               []cDB_Pool     `xml:"Pool"`
	Rule_Set           []cDB_Rule_Set `xml:"Rule_Set"`
	_Attribute_List
}
type cDB_Pool struct {
	Name      _Name        `xml:"name,attr"`
	IPPrefix  netip.Prefix `xml:"IPprefix,attr"`
	RI        _Name        `xml:"RI,attr"`
	SZ        _Name        `xml:"SZ,attr"`
	Port      _Port        `xml:"port,attr"`
	Port_Low  _Port        `xml:"port_low,attr"`
	Port_High _Port        `xml:"port_high,attr"`
	_Attribute_List
}

// Security Rules
type cDB_Rule_Set struct {
	Name _Name        `xml:"name,attr"`
	From []cDB_FromTo `xml:"From"`
	To   []cDB_FromTo `xml:"To"`
	Rule []cDB_Rule   `xml:"Rule"`
	_Attribute_List
}
type cDB_FromTo struct {
	AB        _Name `xml:"AB,attr"`        // NAT_Destination
	IF        _Name `xml:"IF,attr"`        // NAT_Source
	RG        _Name `xml:"RG,attr"`        // NAT_Source
	RI        _Name `xml:"RI,attr"`        // NAT_Source
	SZ        _Name `xml:"SZ,attr"`        // NAT_Source
	Port_Low  _Port `xml:"port_low,attr"`  // NAT_Destination
	Port_High _Port `xml:"port_high,attr"` // NAT_Destination
	_Attribute_List
}
type cDB_Rule struct {
	Name  _Name        `xml:"name,attr"`
	From  []cDB_FromTo `xml:"From"`
	To    []cDB_FromTo `xml:"To"`
	Match []cDB_Match  `xml:"Match"`
	Then  []cDB_Then   `xml:"Then"`
	_Attribute_List
}
type cDB_Match struct {
	Application _Name `xml:"application,attr"`
	_Attribute_List
}
type cDB_Then struct {
	Action      _Action `xml:"action,attr"`
	Action_Flag _Action `xml:"action_flag,attr"`
	Pool        _Name   `xml:"pool,attr"`
	AB          _Name   `xml:"AB,attr"`
	RI          _Name   `xml:"RI,attr"`
	Port_Low    _Port   `xml:"port_low,attr"`
	Port_High   _Port   `xml:"port_high,attr"`
	_Attribute_List
}

// Address Book
type cDB_AB struct {
	Name    _Name            `xml:"name,attr"`
	Set     bool             `xml:"set,attr"`
	Address []cDB_AB_Address `xml:"Address"`
	_Attribute_List
}
type cDB_AB_Address struct {
	AB       _Name        `xml:"AB,attr"`
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	FQDN     _FQDN        `xml:"FQDN,attr"`
	_Attribute_List
}

// Junos Applications
type cDB_JA struct {
	Name _Name         `xml:"name,attr"`
	Term []cDB_JA_Term `xml:"Term"`
	_Attribute_List
}
type cDB_JA_Term struct {
	Name             _Name     `xml:"name,attr"`
	Protocol         _Protocol `xml:"protocol,attr"`
	Source_Port      _Port     `xml:"source_port,attr"`
	Destination_Port _Port     `xml:"destination_port,attr"`
	_Attribute_List
}

// Policy Options
type cDB_PO_PL struct {
	Name  _Name             `xml:"name,attr"`
	Match []cDB_PO_PL_Match `xml:"Match"`
	_Attribute_List
}
type cDB_PO_PL_Match struct {
	IPPrefix netip.Prefix `xml:"IPprefix,attr"`
	_Attribute_List
}
type cDB_PO_PS struct {
	Name _Name            `xml:"name,attr"`
	Term []cDB_PO_PS_Term `xml:"Term"`
	_Attribute_List
}
type cDB_PO_PS_Term struct {
	Name _Name            `xml:"name,attr"`
	From []cDB_PO_PS_From `xml:"From"`
	Then []cDB_PO_PS_Then `xml:"Then"`
	_Attribute_List
}
type cDB_PO_PS_From struct {
	RI         _Name     `xml:"RI,attr"`
	Protocol   _Protocol `xml:"protocol,attr"`
	Route_Type _Type     `xml:"route_type,attr"`
	PL         _Name     `xml:"PL,attr"`
	Mask       _Mask     `xml:"mask,attr"`
	_Attribute_List
}
type cDB_PO_PS_Then struct {
	Action      _Action       `xml:"action,attr"`
	Action_Flag _Action       `xml:"action_flag,attr"`
	Metric      _Route_Weight `xml:"metric,attr"`
	_Attribute_List
}

// Security Policies
type cDB_SP_Option_List struct {
	Default_Policy _Action `xml:"default_policy,attr"`
	_Attribute_List
}

package main

import (
	"encoding/xml"
	"net/netip"
)

// todo: write own xml unmarshaler to avoid double parsing -> get map[index]value instead of []values.

type cDB_AB_Address_List []*cDB_AB_Address
type cDB_AB_List []*cDB_AB
type cDB_FW_FromTo_List []*cDB_FW_FromTo
type cDB_FW_List []*cDB_FW
type cDB_FW_Term_List []*cDB_FW_Term
type cDB_FW_Then_List []*cDB_FW_Then
type cDB_FromTo_List []*cDB_FromTo
type cDB_JA_List []*cDB_JA
type cDB_JA_Term_List []*cDB_JA_Term
type cDB_LDAP_List []*cDB_LDAP
type cDB_Match_List []*cDB_Match
type cDB_N_List map[_Name]*cDB
type cDB_PO_PL_List []*cDB_PO_PL
type cDB_PO_PL_Match_List []*cDB_PO_PL_Match
type cDB_PO_PS_From_List []*cDB_PO_PS_From
type cDB_PO_PS_List []*cDB_PO_PS
type cDB_PO_PS_Term_List []*cDB_PO_PS_Term
type cDB_PO_PS_Then_List []*cDB_PO_PS_Then
type cDB_Peer_IFM_List []*cDB_Peer_IFM
type cDB_Peer_List []*cDB_Peer
type cDB_Peer_RI_IF_IP_List []*cDB_Peer_RI_IF_IP
type cDB_Peer_RI_IF_List []*cDB_Peer_RI_IF
type cDB_Peer_RI_IF_PARP_List []*cDB_Peer_RI_IF_PARP
type cDB_Peer_RI_List []*cDB_Peer_RI
type cDB_Peer_RI_RO_RT_GW_List []*cDB_Peer_RI_RO_RT_GW
type cDB_Peer_RI_RO_RT_List []*cDB_Peer_RI_RO_RT
type cDB_Peer_RI_RO_Route_Leak_FromTo_List []*cDB_Peer_RI_RO_Route_Leak_FromTo
type cDB_Pool_List []*cDB_Pool
type cDB_Rule_List []*cDB_Rule
type cDB_Rule_Set_List []*cDB_Rule_Set
type cDB_SZ_List []*cDB_SZ
type cDB_Then_List []*cDB_Then
type cDB_VI_List []*cDB_VI
type cDB_VI_Peer_List []*cDB_VI_Peer

// cDB root
type cDB struct {
	XMLName     xml.Name
	Domain_Name _FQDN         `xml:"domain_name,attr"` //
	VI_IPPrefix netip.Prefix  `xml:"VI_IPprefix,attr"` //
	VI_Bits     _INet_Routing `xml:"VI_bits,attr"`     //
	UI_IPPrefix netip.Prefix  `xml:"UI_IPprefix,attr"` //
	UI_Bits     _INet_Routing `xml:"UI_bits,attr"`     //
	GT_List     string        `xml:"GT_list,attr"`     //
	Peer        cDB_Peer_List `xml:"Peer_List>Peer"`   //
	VI          cDB_VI_List   `xml:"VI_List>VI"`       //
	LDAP        cDB_LDAP_List `xml:"LDAP_List>LDAP"`   //
	cDB_Vocabulary
	_Attribute_List
}

// LDAP
type cDB_LDAP struct {
	URL          string  `xml:"url,attr"`          //
	Bind_DN      _DN     `xml:"bind_dn,attr"`      //
	Secret       _Secret `xml:"bind_pw,attr"`      //
	DB_Filter    string  `xml:"db_filter,attr"`    //
	DB_CN        string  `xml:"db_cn,attr"`        //
	DC_Filter    string  `xml:"dc_filter,attr"`    //
	DC_CN        string  `xml:"dc_cn,attr"`        //
	Host_Filter  string  `xml:"host_filter,attr"`  //
	Host_CN      string  `xml:"host_cn,attr"`      //
	Group_Filter string  `xml:"group_filter,attr"` //
	Group_CN     string  `xml:"group_cn,attr"`     //
	User_Filter  string  `xml:"user_filter,attr"`  //
	User_CN      string  `xml:"user_cn,attr"`      //
	Admin_DN     string  `xml:"admin_dn,attr"`     //
	CA_Filter    string  `xml:"ca_filter,attr"`    //
	CA_CN        string  `xml:"ca_cn,attr"`        //
	_Attribute_List
}

type cDB_Vocabulary struct {
	AB cDB_AB_List    `xml:"Vocabulary>AB_List>AB"`                   //
	JA cDB_JA_List    `xml:"Vocabulary>Application_List>Application"` //
	PL cDB_PO_PL_List `xml:"Vocabulary>PO>PL"`                        //
	PS cDB_PO_PS_List `xml:"Vocabulary>PO>PS"`                        //
	_Attribute_List
}

// Peer
type cDB_Peer struct {
	ASN             _Inet_ASN          `xml:"ASN,attr"`                 //
	Router_ID       netip.Addr         `xml:"router_ID,attr"`           //
	IFM             cDB_Peer_IFM_List  `xml:"IFM"`                      //
	RI              cDB_Peer_RI_List   `xml:"RI"`                       //
	Hostname        _FQDN              `xml:"hostname,attr"`            //
	Domain_Name     _FQDN              `xml:"domain_name,attr"`         //
	Version         string             `xml:"version,attr"`             //
	Manufacturer    string             `xml:"manufacturer,attr"`        //
	Model           string             `xml:"model,attr"`               //
	Serial          string             `xml:"serial,attr"`              //
	Root            _Secret            `xml:"root,attr"`                //
	GT_List         string             `xml:"GT_list,attr"`             //
	SZ              cDB_SZ_List        `xml:"Security>Zone>SZ"`         //
	NAT_Source      cDB_NAT            `xml:"Security>NAT>Source"`      //
	NAT_Destination cDB_NAT            `xml:"Security>NAT>Destination"` //
	NAT_Static      cDB_NAT            `xml:"Security>NAT>Static"`      //
	SP_Option_List  cDB_SP_Option_List `xml:"Security>SP>Option_List"`  //
	SP_Exact        cDB_Rule_Set_List  `xml:"Security>SP>Exact"`        //
	SP_Global       cDB_Rule_List      `xml:"Security>SP>Global"`       //
	FW              cDB_FW_List        `xml:"Security>FW_List>FW"`      //
	cDB_Vocabulary
	_Attribute_List
}
type cDB_FW struct {
	Name _Name            `xml:"name,attr"` //
	Term cDB_FW_Term_List `xml:"Term"`      //
	_Attribute_List
}
type cDB_FW_Term struct {
	Name _Name              `xml:"name,attr"` //
	From cDB_FW_FromTo_List `xml:"From"`      //
	To   cDB_FW_FromTo_List `xml:"To"`        //
	Then cDB_FW_Then_List   `xml:"Then"`      //
	_Attribute_List
}
type cDB_FW_FromTo struct {
	PL _Name `xml:"PL,attr"` //
	_Attribute_List
}
type cDB_FW_Then struct {
	Action      _W    `xml:"action,attr"`      //
	Action_Flag _W    `xml:"action_flag,attr"` //
	RI          _Name `xml:"RI,attr"`          //
	_Attribute_List
}

type cDB_Peer_IFM struct {
	Name          _Name          `xml:"name,attr"`          //
	Communication _Communication `xml:"communication,attr"` //
	_Attribute_List
}
type cDB_Peer_RI struct {
	Name       _Name                     `xml:"name,attr"`     //
	IF         cDB_Peer_RI_IF_List       `xml:"IF"`            //
	RT         cDB_Peer_RI_RO_RT_List    `xml:"RO>RT"`         //
	Route_Leak cDB_Peer_RI_RO_Route_Leak `xml:"RO>Route_Leak"` //
	_Attribute_List
}
type cDB_Peer_RI_RO_Route_Leak struct {
	Import cDB_Peer_RI_RO_Route_Leak_FromTo_List `xml:"Import"` //
	Export cDB_Peer_RI_RO_Route_Leak_FromTo_List `xml:"Export"` //
	_Attribute_List
}
type cDB_Peer_RI_IF struct {
	Name          _Name                    `xml:"name,attr"`          //
	Communication _Communication           `xml:"communication,attr"` //
	IP            cDB_Peer_RI_IF_IP_List   `xml:"IP"`                 //
	PARP          cDB_Peer_RI_IF_PARP_List `xml:"PARP"`               //
	_Attribute_List
}
type cDB_Peer_RI_IF_IP struct {
	IPPrefix  netip.Prefix `xml:"IPprefix,attr"`  //
	Router_ID bool         `xml:"router_ID,attr"` //
	Primary   bool         `xml:"primary,attr"`   //
	Preferred bool         `xml:"preferred,attr"` //
	NAT       netip.Prefix `xml:"NAT,attr"`       //
	DHCP      bool         `xml:"DHCP,attr"`      //
	_Attribute_List
}
type cDB_Peer_RI_IF_PARP struct {
	IP  netip.Prefix `xml:"IP,attr"`  //
	NAT netip.Prefix `xml:"NAT,attr"` //
	_Attribute_List
}
type cDB_Peer_RI_RO_RT struct {
	Identifier netip.Prefix              `xml:"identifier,attr"` //
	GW         cDB_Peer_RI_RO_RT_GW_List `xml:"GW"`              //
	_Attribute_List
}
type cDB_Peer_RI_RO_RT_GW struct {
	IP          netip.Addr    `xml:"IP,attr"`          //
	IF          _Name         `xml:"IF,attr"`          //
	Table       _Name         `xml:"table,attr"`       //
	Action      _W            `xml:"action,attr"`      //
	Action_Flag _W            `xml:"action_flag,attr"` //
	Metric      _INet_Routing `xml:"metric,attr"`      //
	Preference  _INet_Routing `xml:"preference,attr"`  //
	_Attribute_List
}
type cDB_Peer_RI_RO_Route_Leak_FromTo struct {
	PS _Name `xml:"PS,attr"` //
	_Attribute_List
}

// Virtual Interfaces
type cDB_VI struct {
	ID            _VI_ID           `xml:"ID,attr"`            //
	Type          _Type            `xml:"type,attr"`          //
	Communication _Communication   `xml:"communication,attr"` //
	Route_Metric  _INet_Routing    `xml:"route_metric,attr"`  //
	Peer          cDB_VI_Peer_List `xml:"Peer"`               //
	PSK           _Secret          `xml:"PSK,attr"`           //
	_Attribute_List
}
type cDB_VI_Peer struct {
	ID         _VI_Conn_ID               `xml:"ID,attr"`       //
	ASN        _Inet_ASN                 `xml:"ASN,attr"`      //
	RI         _Name                     `xml:"RI,attr"`       //
	IF         _Name                     `xml:"IF,attr"`       //
	IP         netip.Prefix              `xml:"IP,attr"`       //
	Hub        bool                      `xml:"hub,attr"`      //
	Inner_RI   _Name                     `xml:"inner_RI,attr"` //
	Route_Leak cDB_Peer_RI_RO_Route_Leak `xml:"Route_Leak"`    //
	_Attribute_List
}

// Security
type cDB_SZ struct {
	Name   _Name `xml:"name,attr"`   //
	Screen _Name `xml:"screen,attr"` //
	_Attribute_List
}
type cDB_NAT struct {
	Address_Persistent bool              `xml:"address_persistent,attr"` //
	Pool               cDB_Pool_List     `xml:"Pool"`                    //
	Rule_Set           cDB_Rule_Set_List `xml:"Rule_Set"`                //
	_Attribute_List
}
type cDB_Pool struct {
	Name      _Name        `xml:"name,attr"`      //
	IPPrefix  netip.Prefix `xml:"IPprefix,attr"`  //
	RI        _Name        `xml:"RI,attr"`        //
	SZ        _Name        `xml:"SZ,attr"`        //
	Port      _INet_Port   `xml:"port,attr"`      //
	Port_Low  _INet_Port   `xml:"port_low,attr"`  //
	Port_High _INet_Port   `xml:"port_high,attr"` //
	_Attribute_List
}

// Security Rules
type cDB_Rule_Set struct {
	Name _Name           `xml:"name,attr"` //
	From cDB_FromTo_List `xml:"From"`      //
	To   cDB_FromTo_List `xml:"To"`        //
	Rule cDB_Rule_List   `xml:"Rule"`      //
	_Attribute_List
}
type cDB_FromTo struct {
	AB        _Name      `xml:"AB,attr"`        // NAT_Destination
	IF        _Name      `xml:"IF,attr"`        // NAT_Source
	RG        _Name      `xml:"RG,attr"`        // NAT_Source
	RI        _Name      `xml:"RI,attr"`        // NAT_Source
	SZ        _Name      `xml:"SZ,attr"`        // NAT_Source
	Port_Low  _INet_Port `xml:"port_low,attr"`  // NAT_Destination
	Port_High _INet_Port `xml:"port_high,attr"` // NAT_Destination
	_Attribute_List
}
type cDB_Rule struct {
	Name  _Name           `xml:"name,attr"` //
	From  cDB_FromTo_List `xml:"From"`      //
	To    cDB_FromTo_List `xml:"To"`        //
	Match cDB_Match_List  `xml:"Match"`     //
	Then  cDB_Then_List   `xml:"Then"`      //
	_Attribute_List
}
type cDB_Match struct {
	Application _Name `xml:"application,attr"` //
	_Attribute_List
}
type cDB_Then struct {
	Action      _W         `xml:"action,attr"`      //
	Action_Flag _W         `xml:"action_flag,attr"` //
	Pool        _Name      `xml:"pool,attr"`        //
	AB          _Name      `xml:"AB,attr"`          //
	RI          _Name      `xml:"RI,attr"`          //
	Port_Low    _INet_Port `xml:"port_low,attr"`    //
	Port_High   _INet_Port `xml:"port_high,attr"`   //
	_Attribute_List
}

// Address Book
type cDB_AB struct {
	Name    _Name               `xml:"name,attr"` //
	Set     bool                `xml:"set,attr"`  //
	Address cDB_AB_Address_List `xml:"Address"`   //
	_Attribute_List
}
type cDB_AB_Address struct {
	AB       _Name        `xml:"AB,attr"`       //
	IPPrefix netip.Prefix `xml:"IPprefix,attr"` //
	FQDN     _FQDN        `xml:"FQDN,attr"`     //
	_Attribute_List
}

// Junos Applications
type cDB_JA struct {
	Name _Name            `xml:"name,attr"` //
	Term cDB_JA_Term_List `xml:"Term"`      //
	_Attribute_List
}
type cDB_JA_Term struct {
	Name             _Name          `xml:"name,attr"`             //
	Protocol         _INet_Protocol `xml:"protocol,attr"`         //
	Source_Port      _INet_Port     `xml:"source_port,attr"`      //
	Destination_Port _INet_Port     `xml:"destination_port,attr"` //
	_Attribute_List
}

// Policy Options
type cDB_PO_PL struct {
	Name  _Name                `xml:"name,attr"` //
	Match cDB_PO_PL_Match_List `xml:"Match"`     //
	_Attribute_List
}
type cDB_PO_PL_Match struct {
	IPPrefix netip.Prefix `xml:"IPprefix,attr"` //
	_Attribute_List
}
type cDB_PO_PS struct {
	Name _Name               `xml:"name,attr"` //
	Term cDB_PO_PS_Term_List `xml:"Term"`      //
	_Attribute_List
}
type cDB_PO_PS_Term struct {
	Name _Name               `xml:"name,attr"` //
	From cDB_PO_PS_From_List `xml:"From"`      //
	Then cDB_PO_PS_Then_List `xml:"Then"`      //
	_Attribute_List
}
type cDB_PO_PS_From struct {
	RI         _Name          `xml:"RI,attr"`         //
	Protocol   _INet_Protocol `xml:"protocol,attr"`   //
	Route_Type _Type          `xml:"route_type,attr"` //
	PL         _Name          `xml:"PL,attr"`         //
	Mask       _Mask          `xml:"mask,attr"`       //
	_Attribute_List
}
type cDB_PO_PS_Then struct {
	Action      _W            `xml:"action,attr"`      //
	Action_Flag _W            `xml:"action_flag,attr"` //
	Metric      _INet_Routing `xml:"metric,attr"`      //
	_Attribute_List
}

// Security Policies
type cDB_SP_Option_List struct {
	Default_Policy _W `xml:"default_policy,attr"` //
	_Attribute_List
}

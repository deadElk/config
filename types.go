package main

import (
	"net/netip"

	log "github.com/sirupsen/logrus"
)

type _CN _Name                        //
type _Cipher string                   //
type _Communication string            //
type _Content []byte                  //
type _DER_CRL []byte                  //
type _DER_Cert []byte                 //
type _DER_Key []byte                  //
type _DER_TLS_Client []byte           //
type _DER_TLS_Server []byte           //
type _DN _Name                        //
type _Description string              //
type _FQDN string                     //
type _GID _Name                       //
type _GID_Number _ID                  //
type _ID uint                         //
type _IDName string                   //
type _Name string                     //
type _PName string                    //
type _S string                        //
type _Secret string                   //
type _Service string                  //
type _Type string                     //
type _UID _Name                       //
type _UID_Number _ID                  //
type _W string                        //
type _any struct{ any }               //
type _hash224_ID [_hash224_Size]uint8 // _hash224_ID here a result of sha3.Sum224().
type _hash_ID [_hash_Size]uint8       // _hash_ID here a result of sha3.Sum512().
type _strings []string                //

type _Attribute_List struct { //
	Description _Description `xml:"description,attr"` //
	Deactivate  bool         `xml:"deactivate,attr"`  //
	Reserved    bool         `xml:"reserved,attr"`    //
	Verbosity   log.Level    `xml:"verbosity,attr"`   //
	Patch       string       `xml:"patch,attr"`       //
	Disable     bool         `xml:"disable,attr"`     //
}                                        //
type _Host_Inbound_Traffic_List struct { //
	Services  map[_Service]bool       `xml:"service,attr"`  //
	Protocols map[_INet_Protocol]bool `xml:"protocol,attr"` //
	GT_Action string                  //
}                             //
type _SP_Option_List struct { //
	Default_Policy _W     //
	GT_Action      string //
}                  //
type _BGP struct { //
	BGP_Group       __N_BGP_Group //
	GT_Action       string        //
	_Attribute_List               //
}                        //
type _BGP_Group struct { //
	// 	Type      _Type
	// 	Multipath bool
	Local_ASN       _Inet_ASN              //
	Remote_ASN      _Inet_ASN              //
	Passive         bool                   //
	Neighbor        __A_BGP_Group_Neighbor //
	GT_Action       string                 //
	_Attribute_List                        //
}                                 //
type _BGP_Group_Neighbor struct { //
	Local_ASN       _Inet_ASN             //
	Remote_ASN      _Inet_ASN             //
	Passive         bool                  //
	Local_IP        netip.Addr            //
	Route_Leak      __W_Route_Leak_FromTo //
	GT_Action       string                //
	_Attribute_List                       //
}                               //
type _INet_VI_IP_Table struct { //
	IPPrefix netip.Prefix   //
	Key      _Secret        //
	Conn     []netip.Prefix //
}                               //
type _INet_UI_IP_Table struct { //
	User     *i_LDAP_Domain_User //
	Key      _Secret             //
	Conn     []netip.Prefix      //
	Conn_Key []_Secret           //
}                             //
type _OVPN_GT_Server struct { //
	Address    _FQDN          //
	ExternalIP []netip.Addr   //
	PName      _PName         //
	InternalIP netip.Addr     //
	Netmask    string         //
	Port       _INet_Port     //
	Proto      _INet_Protocol //
	Subnet     string         //
}                             //
type _OVPN_GT_Client struct { //
	Address _FQDN            //
	CA      _PEM_Cert        //
	Cert    _PEM_Cert        //
	Key     _PEM_Key         //
	Netmask string           //
	Port    _INet_Port       //
	Proto   []_INet_Protocol //
	PName   _PName           //
	Subnet  string           //
	TLSv2   _PEM_TLS_Client  //
} //

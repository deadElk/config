package main

import (
	"net/netip"
	"net/url"

	"github.com/go-ldap/ldap/v3"
)

type __DN_LDAP_Domain map[_DN]*i_LDAP_Domain
type __DN_LDAP_Domain_Group map[_DN]*i_LDAP_Domain_Group
type __DN_LDAP_Domain_User map[_DN]*i_LDAP_Domain_User
type __GN_LDAP_Domain_Group map[_GID_Number]*i_LDAP_Domain_Group
type __IPP_LDAP_Domain_User map[netip.Prefix]*i_LDAP_Domain_User
type __UN_LDAP_Domain_User map[_UID_Number]*i_LDAP_Domain_User
type __URL_LDAP map[*url.URL]*i_LDAP
type __FQDN_LDAP_Domain_User map[_FQDN]*i_LDAP_Domain_User

// LDAP
type i_LDAP struct {
	Bind_DN      _DN
	DB_CN        string
	DB_Filter    string
	DC_CN        string
	DC_Filter    string
	Domain       __DN_LDAP_Domain
	Group_CN     string
	Group_Filter string
	M_CN_G       __DN_LDAP_Domain_Group
	M_CN_U       __DN_LDAP_Domain_User
	Modify       *ldap.ModifyRequest
	Modify_Regen map[_FQDN]bool
	OLC          *i_LDAP_OLC // todo: parse OLC from server
	PKI          *_PKI_CA_Node
	Schema       *i_LDAP_Schema // todo: parse schema from server
	Secret       _Secret
	URL          *url.URL
	User_CN      string
	User_Filter  string
}
type i_LDAP_OLC struct {
}
type i_LDAP_Schema struct {
}
type i_LDAP_Domain struct {
	DN        _DN
	Entry     *ldap.Entry
	FQDN      _FQDN
	Group     __GN_LDAP_Domain_Group
	Host      __FQDN_LDAP_Domain_User
	LDAP      *i_LDAP
	Modify    *ldap.ModifyRequest
	OLC       *i_LDAP_Domain_OLC
	PKI       *_PKI_CA_Node
	Raw_DC    *ldap.SearchResult
	Raw_Group *ldap.SearchResult
	Raw_Host  *ldap.SearchResult
	Raw_User  *ldap.SearchResult
	SKV       _SKV
	User      __UN_LDAP_Domain_User
}
type i_LDAP_Domain_OLC struct {
	DN _DN
}
type i_LDAP_Domain_Group struct { // gidNumber: index
	DN             _DN
	Domain         *i_LDAP_Domain
	Entry          *ldap.Entry
	FQDN           _FQDN
	GID            _GID                   // cn
	GID_List       __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< member: index = member (gidNumber here), value is a pointer.
	GID_Number     _GID_Number
	LDAP           *i_LDAP
	Modify         *ldap.ModifyRequest
	Owner_GID_List __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< owner: index = owner (gidNumber here), value is a pointer.
	Owner_UID_List __UN_LDAP_Domain_User  // owner: index = owner (uidNumber here), value is a pointer.
	PKI            *_PKI_Node
	SKV            _SKV
	UID_List       __UN_LDAP_Domain_User // member: index = member (uidNumber here), value is a pointer.
	VPN            *i_LDAP_Domain_Group_VPN
	VPN_SKV        _SKV
}
type i_LDAP_Domain_Group_VPN struct {
	Outside_IPPrefix map[string]string
	SSP              bool
	Port             _INet_Port
	FW_v00           map[string]string
	TLSv2            _PEM
	TLSv2_User       map[_UID_Number][]_PEM
}

type i_LDAP_Domain_User struct { // uidNumber: index
	LDAP       *i_LDAP
	DN         _DN
	Domain     *i_LDAP_Domain
	Entry      *ldap.Entry
	FQDN       _FQDN
	GID_List   __GN_LDAP_Domain_Group // memberOf: index = memberOf (gidNumber here), value is a pointer.
	GID_Number _GID_Number            // gidNumber
	IPPrefix   netip.Prefix           // ipHostNumber (user's subnet)
	Modify     *ldap.ModifyRequest
	SKV        _SKV // sshPublicKey, userPKCS12, etc: private [service][key]value DB
	UID        _UID // uid
	UID_Number _UID_Number
	PKI        __PKI_Node
}

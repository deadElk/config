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
type __P_LDAP_Domain_User map[netip.Prefix]*i_LDAP_Domain_User
type __UN_LDAP_Domain_User map[_UID_Number]*i_LDAP_Domain_User
type __U_LDAP map[*url.URL]*i_LDAP

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
	OLC          *i_LDAP_OLC    // todo: parse OLC from server
	Schema       *i_LDAP_Schema // todo: parse schema from server
	Secret       _Secret
	URL          *url.URL
	User_CN      string
	User_Filter  string
	PKI          *_PKI_CA_Node
}
type i_LDAP_OLC struct {
}
type i_LDAP_Schema struct {
}
type i_LDAP_Domain struct {
	LDAP      *i_LDAP
	DN        _DN
	Entry     *ldap.Entry
	FQDN      _FQDN
	Group     __GN_LDAP_Domain_Group
	Modify    *ldap.ModifyRequest
	OLC       *i_LDAP_Domain_OLC
	Raw_DC    *ldap.SearchResult
	Raw_Group *ldap.SearchResult
	Raw_User  *ldap.SearchResult
	SKV       _SKV
	User      __UN_LDAP_Domain_User
	PKI       *_PKI_CA_Node
}
type i_LDAP_Domain_OLC struct {
	DN _DN
}
type i_LDAP_Domain_Group struct { // gidNumber: index
	LDAP           *i_LDAP
	DN             _DN
	Domain         *i_LDAP_Domain
	Entry          *ldap.Entry
	FQDN           _FQDN
	GID            _GID                   // cn
	GID_List       __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< member: index = member (gidNumber here), value is a pointer.
	GID_Number     _GID_Number
	Modify         *ldap.ModifyRequest
	Owner_GID_List __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< owner: index = owner (gidNumber here), value is a pointer.
	Owner_UID_List __UN_LDAP_Domain_User  // owner: index = owner (uidNumber here), value is a pointer.
	SKV            _SKV
	UID_List       __UN_LDAP_Domain_User // member: index = member (uidNumber here), value is a pointer.
	PKI            *_PKI_Node
	VPN            *i_LDAP_VPN
}
type i_LDAP_VPN struct {
	outside_IPPrefix map[netip.Prefix]bool
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

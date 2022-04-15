package main

import (
	"net/netip"
	"net/url"

	"github.com/go-ldap/ldap/v3"
)

type __DN_LDAP_Domain map[_DN]*i_LDAP_Domain                     //
type __DN_LDAP_Domain_Group map[_DN]*i_LDAP_Domain_Group         //
type __DN_LDAP_Domain_Host map[_DN]*i_LDAP_Domain_Host           //
type __DN_LDAP_Domain_User map[_DN]*i_LDAP_Domain_User           //
type __GN_LDAP_Domain_Group map[_GID_Number]*i_LDAP_Domain_Group //
type __IPP_LDAP_Domain_User map[netip.Prefix]*i_LDAP_Domain_User //
type __S_LDAP_SKV map[string]*i_LDAP_SKV                         //
type __UN_LDAP_Domain_User map[_UID_Number]*i_LDAP_Domain_User   //
type __URL_LDAP map[*url.URL]*i_LDAP                             //

type i_LDAP struct {
	Bind_DN      _DN                    //
	DB_CN        string                 //
	DB_Filter    string                 //
	DC_CN        string                 //
	DC_Filter    string                 //
	Domain       __DN_LDAP_Domain       //
	Group_CN     string                 //
	Group_Filter string                 //
	Host_CN      string                 //
	Host_Filter  string                 //
	Admin_DN     _strings               //
	CA_Filer     string                 //
	CA_CN        string                 //
	M_CN_G       __DN_LDAP_Domain_Group //
	M_CN_U       __DN_LDAP_Domain_User  //
	Modify       *ldap.ModifyRequest    //
	PKI          *_PKI_Container        //
	Secret       _Secret                //
	URL          *url.URL               //
	User_CN      string                 //
	User_Filter  string                 //

	// OLC          *i_LDAP_OLC            // todo: parse OLC from server
	// Schema       *i_LDAP_Schema         // todo: parse schema from server
}
type i_LDAP_OLC struct {
}
type i_LDAP_Schema struct {
}
type i_LDAP_Domain struct {
	DN        _DN                    //
	Entry     *ldap.Entry            //
	FQDN      _FQDN                  //
	Group     __GN_LDAP_Domain_Group //
	Host      __DN_LDAP_Domain_Host  //
	LDAP      *i_LDAP                //
	Modify    *ldap.ModifyRequest    //
	PKI       *_PKI_Container        //
	Raw_DC    *ldap.SearchResult     //
	Raw_CA    *ldap.SearchResult     //
	Raw_Group *ldap.SearchResult     //
	Raw_Host  *ldap.SearchResult     //
	Raw_User  *ldap.SearchResult     //
	SKV       __S_LDAP_SKV           //
	User      __UN_LDAP_Domain_User  //
	// OLC *i_LDAP_Domain_OLC            //
}
type i_LDAP_Domain_OLC struct {
	DN _DN //
}
type i_LDAP_Domain_Group struct {
	DN             _DN                    //
	Domain         *i_LDAP_Domain         //
	Entry          *ldap.Entry            //
	FQDN           _FQDN                  //
	FW_v00         []string               //
	GID            _GID                   // cn
	GID_List       __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< member: index = member (gidNumber here), value is a pointer.
	GID_Number     _GID_Number            //
	LDAP           *i_LDAP                //
	Modify         *ldap.ModifyRequest    //
	OVPN           *i_LDAP_Domain_Host    //
	Owner_GID_List __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< owner: index = owner (gidNumber here), value is a pointer.
	Owner_UID_List __UN_LDAP_Domain_User  // owner: index = owner (uidNumber here), value is a pointer.
	PKI            *_PKI_Container        //
	SKV            __S_LDAP_SKV           //
	UID_List       __UN_LDAP_Domain_User  // member: index = member (uidNumber here), value is a pointer.
}
type i_LDAP_Domain_User struct {
	DN         _DN                    //
	Domain     *i_LDAP_Domain         //
	Entry      *ldap.Entry            //
	FQDN       _FQDN                  //
	GID_List   __GN_LDAP_Domain_Group // memberOf: index = memberOf (gidNumber here), value is a pointer.
	GID_Number _GID_Number            // gidNumber
	IPPrefix   netip.Prefix           // ipHostNumber (user's subnet)
	LDAP       *i_LDAP                //
	Modify     *ldap.ModifyRequest    //
	PKI        __PKI_Container        //
	SKV        __S_LDAP_SKV           // sshPublicKey, userPKCS12, etc: private [service][key]value DB
	UID        _UID                   // uid
	UID_Number _UID_Number            //
}

type i_LDAP_Domain_Host struct {
	Address    _FQDN                             //
	DN         _DN                               //
	Domain     *i_LDAP_Domain                    //
	Entry      *ldap.Entry                       //
	FQDN       _FQDN                             //
	IPPrefix   netip.Prefix                      //
	LDAP       *i_LDAP                           //
	Modify     *ldap.ModifyRequest               //
	PKI        *_PKI_Container                   //
	PName      _PName                            //
	PPort      _PName                            //
	Port       _INet_Port                        //
	SKV        __S_LDAP_SKV                      //
	SSH_Client []string                          // ssh client key
	TLSv2      _PEM_TLS_Server                   //
	TLSv2_User map[_UID_Number][]_PEM_TLS_Client //
	// FW_v00     []string               //
}
type i_LDAP_SKV struct {
	Value   map[string]bool //
	Ordered []string        //
}

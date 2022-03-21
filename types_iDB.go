package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/netip"
	"net/url"

	"github.com/go-ldap/ldap/v3"
)

type __A_Peer map[_Inet_ASN]*i_Peer
type __A_Peer_Group map[_Inet_ASN]*i_Peer_Group
type __DN_LDAP_Domain map[_DN]*i_LDAP_Domain
type __DN_LDAP_Domain_Group map[_DN]*i_LDAP_Domain_Group
type __DN_LDAP_Domain_User map[_DN]*i_LDAP_Domain_User
type __GN_LDAP_Domain_Group map[_GID_Number]*i_LDAP_Domain_Group
type __INet_UI_IP_Table map[netip.Prefix]*_INet_UI_IP_Table
type __INet_VI_IP_Table map[_VI_ID]*_INet_VI_IP_Table
type __N_AB map[_Name]*i_AB
type __N_AB_Set map[_Name]*i_AB_Set
type __N_Content map[_Name]_Content
type __N_File_Data map[_Name]*i_File_Data
type __N_JA map[_Name]*i_JA
type __N_Name map[_Name]_Name
type __I_SKV_DB_Key map[_ID]*_SKV_DB_Key
type __N_SKV_DB_Value map[_Name]*_SKV_DB_Value
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
type __P_LDAP_Domain_User map[netip.Prefix]*i_LDAP_Domain_User
type __P_Peer_RI_IF map[netip.Prefix]*i_Peer_RI_IF
type __P_Peer_RI_IF_IP map[netip.Prefix]*i_Peer_RI_IF_IP
type __P_Peer_RI_IF_PARP map[netip.Prefix]*i_Peer_RI_IF_PARP
type __P_Peer_RI_RO_RT map[netip.Prefix]*i_Peer_RI_RO_RT
type __T_Peer_NAT_Type map[_Type]*i_Peer_NAT_Type
type __UN_LDAP_Domain_User map[_UID_Number]*i_LDAP_Domain_User
type __U_LDAP map[*url.URL]*i_LDAP
type __W_Route_Leak_FromTo map[_W]*i_Route_Leak_FromTo
type __i_FW []*i_FW
type __i_FW_FromTo []*i_FW_FromTo
type __i_FW_Term []*i_FW_Term
type __i_FW_Then []*i_FW_Then
type __i_FromTo []*i_FromTo
type __i_ID_Peer map[_VI_Conn_ID]*i_VI_Peer
type __i_JA_Term []*i_JA_Term
type __i_PO_PL_Match []*i_PO_PL_Match
type __i_PO_PS_From []*i_PO_PS_From
type __i_PO_PS_Term []*i_PO_PS_Term
type __i_PO_PS_Then []*i_PO_PS_Then
type __i_Rule []*i_Rule
type __i_Rule_Set []*i_Rule_Set
type __i_Then []*i_Then
type __i_VI map[_VI_ID]*i_VI
type __i_VI_GT map[_VI_ID]*i_VI_GT
type __i_VI_ID_Peer map[_VI_ID]__i_ID_Peer
type __i_VI_Peer map[_VI_ID]*i_VI_Peer

// file i/o
type i_File_Data struct {
	ext    _Name
	sorted []_Name
	data   __N_Content
}

// PKI
type _PKI struct { // PEM?
	*_PKI_CA_Node
	Domain map[_FQDN]*_PKI_Domain
}
type _PKI_Domain struct {
	*_PKI_Node
	Host  map[_FQDN]*_PKI_Node
	Group map[_FQDN]*_PKI_Node
	User  map[_FQDN]*_PKI_Node
}
type _PKI_CA_Node struct {
	DER *_PKI_CA_Node_DER
	PEM *_PKI_CA_Node_PEM
	P12 []byte
}
type _PKI_CA_Node_DER struct {
	CA  *x509.Certificate
	Key *ecdsa.PrivateKey
	CRL *pkix.CertificateList
}
type _PKI_CA_Node_PEM struct {
	CA  []byte
	Key []byte
	CRL []byte
}
type _PKI_Node struct {
	DER *_PKI_Node_DER
	PEM *_PKI_Node_PEM
	P12 []byte
}
type _PKI_Node_DER struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}
type _PKI_Node_PEM struct {
	Cert []byte
	Key  []byte
}

// LDAP
type i_LDAP struct {
	URL          *url.URL
	Bind_DN      _DN
	Secret       _Secret
	DB_Filter    string
	DB_CN        string
	DC_Filter    string
	DC_CN        string
	Group_Filter string
	Group_CN     string
	User_Filter  string
	User_CN      string
	OLC          *i_LDAP_OLC    // todo: parse OLC from server
	Schema       *i_LDAP_Schema // todo: parse schema from server
	Domain       __DN_LDAP_Domain
	M_CN_G       __DN_LDAP_Domain_Group
	M_CN_U       __DN_LDAP_Domain_User
	Modify       *ldap.ModifyRequest
	Modify_Regen map[_FQDN]bool
}
type i_LDAP_OLC struct {
}
type i_LDAP_Schema struct {
}
type i_LDAP_Domain struct {
	DN        _DN
	OLC       *i_LDAP_Domain_OLC
	Group     __GN_LDAP_Domain_Group
	User      __UN_LDAP_Domain_User
	Raw_DC    *ldap.SearchResult
	Raw_Group *ldap.SearchResult
	Raw_User  *ldap.SearchResult
	SKV       __I_SKV_DB_Key
	Modify    *ldap.ModifyRequest
	Entry     *ldap.Entry
}
type i_LDAP_Domain_OLC struct {
	DN _DN
}
type i_LDAP_Domain_Group struct { // gidNumber: index
	DN             _DN
	GID_Number     _GID_Number
	GID            _GID                   // cn
	UID_List       __UN_LDAP_Domain_User  // member: index = member (uidNumber here), value is a pointer.
	GID_List       __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< member: index = member (gidNumber here), value is a pointer.
	Owner_UID_List __UN_LDAP_Domain_User  // owner: index = owner (uidNumber here), value is a pointer.
	Owner_GID_List __GN_LDAP_Domain_Group // CAUTION >>>> GID includes GID <<<< owner: index = owner (gidNumber here), value is a pointer.
	Modify         *ldap.ModifyRequest
	Entry          *ldap.Entry
}
type i_LDAP_Domain_User struct { // uidNumber: index
	DN         _DN
	UID_Number _UID_Number
	UID        _UID                   // uid
	GID_Number _GID_Number            // gidNumber
	IPPrefix   netip.Prefix           // ipHostNumber (user's subnet)
	GID_List   __GN_LDAP_Domain_Group // memberOf: index = memberOf (gidNumber here), value is a pointer.
	SKV        __I_SKV_DB_Key         // sshPublicKey, userPKCS12, etc: private [service][key]value DB
	Modify     *ldap.ModifyRequest
	Entry      *ldap.Entry
}
type _SKV_DB_Key struct {
	Value __N_SKV_DB_Value
}
type _SKV_DB_Value struct {
	Protocol _INet_Protocol
	Cipher   _Cipher
	URL      *url.URL
	Secret   _Secret
}

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
	Peer_List           __A_Peer
	GT_Action           string
	_Attribute_List
}

// Peer
type i_Peer struct {
	// VI           __i_VI
	// VI_Local     __i_VI_Peer
	// VI_Remote    __i_VI_Peer
	Group        *i_Peer_Group
	ASN          _Inet_ASN
	ASName       _Name
	PName        _PName
	Router_ID    netip.Addr
	IF_2_RI      __N_Name // interface to RI mapping. interfaces within one peer must be unique.
	VI_GT        __i_VI_GT
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
	FW           __i_FW
	IKE_GCM      bool
	GT_Action    string
	_Attribute_List
}

type i_FW struct {
	Name      _Name
	Term      __i_FW_Term
	GT_Action string
	_Attribute_List
}
type i_FW_Term struct {
	Name      _Name
	From      __i_FW_FromTo
	To        __i_FW_FromTo
	Then      __i_FW_Then
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
	Exact       __i_Rule_Set
	Global      __i_Rule
	GT_Action   string
}
type i_Peer_IFM struct {
	Communication _Communication
	GT_Action     string
	_Attribute_List
}
type i_Peer_RI struct {
	IP_IF map[netip.Prefix]_Name // interface's IP address to interface mapping. IP addresses within one RI must be unique.
	// IP_IF       __P_Peer_RI_IF
	// IPPrefix_IF __P_Peer_RI_IF
	// IPMasked_IF __P_Peer_RI_IF
	IF         __N_Peer_RI_IF
	RT         __P_Peer_RI_RO_RT
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
	IP            __P_Peer_RI_IF_IP
	PARP          __P_Peer_RI_IF_PARP
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
	From      __i_FromTo
	To        __i_FromTo
	Rule      __i_Rule
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
	Name      _Name      // SP
	JA        []_Name    // SP, NAT
	From      __i_FromTo // SP, NAT
	To        __i_FromTo // SP, NAT
	Then      __i_Then   // SP, NAT
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
	Term      __i_JA_Term
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
	Match     __i_PO_PL_Match
	GT_Action string
	_Attribute_List
}
type i_PO_PL_Match struct {
	IPPrefix  netip.Prefix
	GT_Action string
	_Attribute_List
}
type i_PO_PS struct {
	Term      __i_PO_PS_Term
	GT_Action string
	_Attribute_List
}
type i_PO_PS_Term struct {
	Name      _Name
	From      __i_PO_PS_From
	Then      __i_PO_PS_Then
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

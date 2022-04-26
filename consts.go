package main

import (
	log "github.com/sirupsen/logrus"
)

const (
	_next_ID      _ID   = iota
	_next_IDName  _Name = "next_ID"
	_hash_Size    int   = 512 / 8
	_hash224_Size int   = 224 / 8
)
const (
	_service  string = "config"
	_serviced        = _service /*+ "d"*/
	_SERVICE  string = "CONFIG"
	_SERVICED        = _SERVICE /*+ "D"*/
)
const (
	_re_comma      string = ","
	_re_digit      string = "0123456789"
	_re_dog        string = "@"
	_re_equal      string = "="
	_re_lower_case string = "abcdefghijklmnopqrstuvwxyz"
	_re_point      string = "."
	_re_space      string = " "
	_re_symbol     string = "_" // carefully with a special symbols
	_re_upper_case string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_passwd               = _re_upper_case + _re_lower_case + _re_digit + _re_symbol
)
const (
	_comm_if _ID = iota
	_comm_vi
)
const (
	// _dir_PKI      _Dir_Name = "tmp/PKI"
	// _dir_PKI_CRL  _Dir_Name = "tmp/PKI/CRL"
	// _dir_PKI_Key  _Dir_Name = "tmp/PKI/Key"
	// _dir_PKI_P12  _Dir_Name = "tmp/PKI/P12"
	_dir_Config              _Dir_Name = "tmp/CONFIG"
	_dir_Data                _Dir_Name = "tmp/data"
	_dir_GT                  _Dir_Name = "etc/templates"
	_dir_GT_OVPN             _Dir_Name = "etc/templates/openvpn"
	_dir_LDAP                _Dir_Name = "tmp/LDAP"
	_dir_Modify              _Dir_Name = "tmp/modify"
	_dir_PKI_TLS             _Dir_Name = "tmp/PKI/TLS"
	_dir_PKI_CA              _Dir_Name = "tmp/PKI/CA"
	_dir_PKI_Cert            _Dir_Name = "tmp/PKI/Cert"
	_dir_Portal              _Dir_Name = "tmp/portal"
	_dir_ULE                 _Dir_Name = "/usr/local/etc"
	_dir_Stage               _Dir_Name = "tmp/stage"
	_dir_Stage_OVPN                    = _dir_Stage + "/openvpn"
	_dir_Stage_OVPN_ULE                = _dir_Stage_OVPN + _dir_ULE
	_dir_Stage_OVPN_ULE_OVPN           = _dir_Stage_OVPN_ULE + "/openvpn"
	_dir_Stage_OVPN_ULE_Cron           = _dir_Stage_OVPN_ULE + "/cron.d"
	_dir_Stage_OVPN_ULE_RC_D           = _dir_Stage_OVPN_ULE + "/rc.d"

	_dir_etc _Dir_Name = "etc"
)
const (
	_file_host_list _File_Name = "host_list.txt"
	_file_openvpn   _File_Name = "/usr/local/sbin/openvpn"
)
const (
	_lURI_firewall_v00     = "firewall_v00"
	_lURI_openvpn          = "openvpn"
	_lURI_revoke           = "revoke"
	_lURI_openvpnd_address = "openvpnd_address"
	_lURI_openvpnd_ip      = "openvpnd_ip"
	_lURI_openvpnd_port    = "openvpnd_port"
	_skv_CA                = "cACertificate"
	_skv_CRL               = "certificateRevocationList"
	_skv_P12               = "userPKCS12"
	_skv_SSH_PK            = "sshPublicKey"
	_skv_cn                = "cn"
	_skv_dn                = "dn"
	_skv_entryDN           = "entryDN"
	_skv_etc               = ""
	_skv_gidNumber         = "gidNumber"
	_skv_ipHostNumber      = "ipHostNumber"
	_skv_labeledURI        = "labeledURI"
	_skv_member            = "member"
	_skv_owner             = "owner"
	_skv_sn                = "sn"
	_skv_uid               = "uid"
	_skv_uidNumber         = "uidNumber"
)
const (
	_S_Verbosity                        = log.InfoLevel
	_S_Domain_Name         _FQDN        = "example.net"
	_S_Group               _Inet_ASN    = 4200000000
	_S_Host_RI                          = _Name_junos_host
	_S_Master_RI                        = _Name_master
	_S_Mgmt_IF                          = _Name_fxp0_0
	_S_Mgmt_RI                          = _Name_mgmt_junos
	_S_Mgmt_RI_Description _Description = "MANAGEMENT-INSTANCE"
	_S_SP_Default_Policy                = _W_permit__all
	_S_VI_RI                            = _Name_VI
	_S_cn_ca                            = string(_W_ou)
	_S_cn_config                        = string(_W_cn____config)
	_S_cn_db                            = string(_W_olcSuffix)
	_S_cn_dc                            = string(_W_dn)
	_S_cn_group                         = string(_W_cn)
	_S_cn_host                          = string(_W_cn)
	_S_cn_user                          = string(_W_uid)
	_S_filter_ca                        = "(&(objectClass=pkiCA)(ou=CA))"
	_S_filter_db                        = string(_W_objectClass_olcDatabaseConfig_objectClass_olcMdbConfig)
	_S_filter_dc                        = string(_W_objectClass_dcObject)
	_S_filter_group                     = string(_W_objectClass_posixGroup)
	_S_filter_host                      = "(&(objectClass=inetOrgPerson)(labeledURI=host))"
	_S_filter_user                      = string(_W_objectClass_posixAccount)
	_S_sn                               = string(_W_sn)
)
const (
	_Communication_ptmp = _Communication(_W_ptmp)
	_Communication_ptp  = _Communication(_W_ptp)
)
const (
	_Route_Weight_bits_per_rm _INet_Routing = 2
	_Route_Weight_max_rm                    = 32/_Route_Weight_bits_per_rm - 1
	_VIx_Addr                               = "192.168.0.0"
	_VIx_mask                 _INet_Routing = 16
	_VIx_bits                               = 32 - _VIx_mask
	_VIx_IF_bits              _INet_Routing = 2
	_VIx_total                _INet_Routing = 1 << (_VIx_bits - _VIx_IF_bits)
	_UIx_Addr                               = "172.16.0.0"
	_UIx_mask                 _INet_Routing = 12
	_UIx_bits                               = 32 - _UIx_mask
	_UIx_IP_bits              _INet_Routing = 5
	_UIx_IP_mask                            = 32 - _UIx_IP_bits
	_UIx_IPx                  _INet_Routing = 1 << _UIx_IP_bits
	_UIx_total                _INet_Routing = 1 << (_UIx_bits - _UIx_IP_bits)
)
const (
	_Mask_exact    = _Mask(_W_exact)
	_Mask_longer   = _Mask(_W_longer)
	_Mask_orlonger = _Mask(_W_orlonger)
)
const (
	_Name_AS         = _Name(_W_AS)
	_Name_ID         = _Name(_W_ID)
	_Name_PUBLIC     = _Name(_W_PUBLIC)
	_Name_VI         = _Name(_W_VI)
	_Name_any        = _Name(_W_any)
	_Name_fxp0       = _Name(_W_fxp0)
	_Name_fxp0_0     = _Name(_W_fxp0_0)
	_Name_gr0        = _Name(_W_gr0)
	_Name_junos_host = _Name(_W_junos__host)
	_Name_lo0        = _Name(_W_lo0)
	_Name_lo0_0      = _Name(_W_lo0_0)
	_Name_lt0        = _Name(_W_lt0)
	_Name_master     = _Name(_W_master)
	_Name_mgmt_junos = _Name(_W_mgmt_junos)
	_Name_st0        = _Name(_W_st0)
)
const (
	_Protocol_access_internal = _INet_Protocol(_W_access__internal)
	_Protocol_aggregate       = _INet_Protocol(_W_aggregate)
	_Protocol_ah              = _INet_Protocol(_W_ah)
	_Protocol_all             = _INet_Protocol(_W_all)
	_Protocol_arp             = _INet_Protocol(_W_arp)
	_Protocol_bgp             = _INet_Protocol(_W_bgp)
	_Protocol_direct          = _INet_Protocol(_W_direct)
	_Protocol_egp             = _INet_Protocol(_W_egp)
	_Protocol_esp             = _INet_Protocol(_W_esp)
	_Protocol_gre             = _INet_Protocol(_W_gre)
	_Protocol_icmp            = _INet_Protocol(_W_icmp)
	_Protocol_icmp6           = _INet_Protocol(_W_icmp6)
	_Protocol_igmp            = _INet_Protocol(_W_igmp)
	_Protocol_ipip            = _INet_Protocol(_W_ipip)
	_Protocol_local           = _INet_Protocol(_W_local)
	_Protocol_ospf            = _INet_Protocol(_W_ospf)
	_Protocol_pim             = _INet_Protocol(_W_pim)
	_Protocol_rsvp            = _INet_Protocol(_W_rsvp)
	_Protocol_sctp            = _INet_Protocol(_W_sctp)
	_Protocol_static          = _INet_Protocol(_W_static)
	_Protocol_tcp             = _INet_Protocol(_W_tcp)
	_Protocol_udp             = _INet_Protocol(_W_udp)
)
const (
	_Service_all         = _Service(_W_all)
	_Service_any_service = _Service(_W_any__service)
	_Service_bootp       = _Service(_W_bootp)
	_Service_dhcp        = _Service(_W_dhcp)
	_Service_dhcpv6      = _Service(_W_dhcpv6)
	_Service_ike         = _Service(_W_ike)
	_Service_ping        = _Service(_W_ping)
	_Service_snmp        = _Service(_W_snmp)
	_Service_snmp_trap   = _Service(_W_snmp__trap)
	_Service_ssh         = _Service(_W_ssh)
	_Service_traceroute  = _Service(_W_traceroute)
)
const (
	_Type_destination      = _Type(_W_destination)
	_Type_exact            = _Type(_W_exact)
	_Type_external         = _Type(_W_external)
	_Type_firewall         = _Type(_W_firewall)
	_Type_fqdn             = _Type(_W_fqdn)
	_Type_from             = _Type(_W_from)
	_Type_fxp              = _Type(_W_fxp)
	_Type_global           = _Type(_W_global)
	_Type_gr               = _Type(_W_gr)
	_Type_internal         = _Type(_W_internal)
	_Type_ipprefix         = _Type(_W_ipprefix)
	_Type_lo               = _Type(_W_lo)
	_Type_lt               = _Type(_W_lt)
	_Type_policy_statement = _Type(_W_policy__statement)
	_Type_pool             = _Type(_W_pool)
	_Type_set              = _Type(_W_set)
	_Type_source           = _Type(_W_source)
	_Type_st               = _Type(_W_st)
	_Type_static           = _Type(_W_static)
	_Type_template         = _Type(_W_template)
	_Type_then             = _Type(_W_then)
	_Type_to               = _Type(_W_to)
)
const (
	_W_AS                                                     _W = "AS"
	_W_Class                                                  _W = "Class"
	_W_Config                                                 _W = "Config"
	_W_Database                                               _W = "Database"
	_W_ID                                                     _W = "ID"
	_W_PUBLIC                                                 _W = "OUTER_LIST"
	_W_VI                                                     _W = "VI"
	_W_accept                                                 _W = "accept"
	_W_access                                                 _W = "access"
	_W_access__internal                                          = _W_access + "-" + _W_internal
	_W_add                                                    _W = "add"
	_W_address                                                _W = "address"
	_W_address__book                                             = _W_address + "-" + _W_book
	_W_address__set                                              = _W_address + "-" + _W_set
	_W_aggregate                                              _W = "aggregate"
	_W_ah                                                     _W = "ah"
	_W_all                                                    _W = "all"
	_W_any                                                    _W = "any"
	_W_any__service                                              = _W_any + "-" + _W_service
	_W_application                                            _W = "application"
	_W_applications                                              = _W_application + "s"
	_W_applications____application                               = _W_applications + " " + _W_application
	_W_arp                                                    _W = "arp"
	_W_balance                                                _W = "balance"
	_W_bgp                                                    _W = "bgp"
	_W_book                                                   _W = "book"
	_W_bootp                                                  _W = "bootp"
	_W_cn                                                     _W = "cn"
	_W_cn____config                                              = _W_cn + "=" + _W_config
	_W_config                                                 _W = "config"
	_W_dc                                                     _W = "dc"
	_W_dcObject                                                  = _W_dc + "Object"
	_W_deny                                                   _W = "deny"
	_W_deny__all                                                 = _W_deny + "-" + _W_all
	_W_destination                                            _W = "destination"
	_W_destination__address                                      = _W_destination + "-" + _W_address
	_W_destination__address__name                                = _W_destination__address + "-" + _W_name
	_W_destination__nat                                          = _W_destination + "-" + _W_nat
	_W_destination__port                                         = _W_destination + "-" + _W_port
	_W_destination__prefix__list                                 = _W_destination + "-" + _W_prefix__list
	_W_dhcp                                                   _W = "dhcp"
	_W_dhcpv6                                                    = _W_dhcp + _W_v6
	_W_direct                                                 _W = "direct"
	_W_discard                                                _W = "discard"
	_W_dn                                                     _W = "dn"
	_W_dns                                                    _W = "dns"
	_W_dns__name                                                 = _W_dns + "-" + _W_name
	_W_egp                                                    _W = "egp"
	_W_esp                                                    _W = "esp"
	_W_exact                                                  _W = "exact"
	_W_export                                                 _W = "export"
	_W_export_metric                                             = _W_export + "_" + _W_metric
	_W_external                                               _W = "external"
	_W_filter                                                 _W = "filter"
	_W_firewall                                               _W = "firewall"
	_W_firewall___filter                                         = _W_firewall + " " + _W_filter
	_W_fqdn                                                   _W = "fqdn"
	_W_from                                                   _W = "from"
	_W_from___destination__prefix__list                          = _W_from + " " + _W_destination__prefix__list
	_W_from___routing__instance                                  = _W_from + " " + _W_routing__instance
	_W_from___source__prefix__list                               = _W_from + " " + _W_source__prefix__list
	_W_from___zone                                               = _W_from + " " + _W_zone
	_W_from__zone                                                = _W_from + "-" + _W_zone
	_W_fxp                                                    _W = "fxp"
	_W_fxp0                                                      = _W_fxp + "0"
	_W_fxp0_0                                                    = _W_fxp0 + ".0"
	_W_global                                                 _W = "global"
	_W_gr                                                     _W = "gr"
	_W_gr0                                                       = _W_gr + "0"
	_W_gre                                                    _W = "gre"
	_W_group                                                  _W = "group"
	_W_hop                                                    _W = "hop"
	_W_host                                                   _W = "host"
	_W_host__inbound__traffic                                    = _W_host + "-" + _W_inbound + "-" + _W_traffic
	_W_icmp                                                   _W = "icmp"
	_W_icmp6                                                     = _W_icmp + "6"
	_W_if                                                     _W = "if"
	_W_igmp                                                   _W = "igmp"
	_W_ike                                                    _W = "ike"
	_W_import                                                 _W = "import"
	_W_import_metric                                             = _W_import + "_" + _W_metric
	_W_inbound                                                _W = "inbound"
	_W_instance                                               _W = "instance"
	_W_interface                                              _W = "interface"
	_W_interfaces                                                = _W_interface + "s"
	_W_internal                                               _W = "internal"
	_W_ip                                                     _W = "ip"
	_W_ipip                                                      = _W_ip + _W_ip
	_W_ipprefix                                                  = _W_ip + _W_prefix
	_W_junos                                                  _W = "junos"
	_W_junos__host                                               = _W_junos + "-" + _W_host
	_W_link                                                   _W = "link"
	_W_list                                                   _W = "list"
	_W_lo                                                     _W = "lo"
	_W_lo0                                                       = _W_lo + "0"
	_W_lo0_0                                                     = _W_lo0 + ".0"
	_W_load                                                   _W = "load"
	_W_load__balance                                             = _W_load + "-" + _W_balance
	_W_local                                                  _W = "local"
	_W_log                                                    _W = "log"
	_W_longer                                                 _W = "longer"
	_W_lt                                                     _W = "lt"
	_W_lt0                                                       = _W_lt + "0"
	_W_mapped                                                 _W = "mapped"
	_W_mapped__port                                              = _W_mapped + "-" + _W_port
	_W_master                                                 _W = "master"
	_W_member                                                 _W = "member"
	_W_metric                                                 _W = "metric"
	_W_mgmt                                                   _W = "mgmt"
	_W_mgmt_junos                                                = _W_mgmt + "_" + _W_junos
	_W_name                                                   _W = "name"
	_W_nat                                                    _W = "nat"
	_W_neighbor                                               _W = "neighbor"
	_W_next                                                   _W = "next"
	_W_next__hop                                                 = _W_next + "-" + _W_hop
	_W_next__table                                               = _W_next + "-" + _W_table
	_W_object                                                 _W = "object"
	_W_objectClass                                               = _W_object + _W_Class
	_W_objectClass_dcObject                                      = "(" + _W_objectClass + "=" + _W_dcObject + ")"
	_W_objectClass_olcDatabaseConfig_objectClass_olcMdbConfig    = "(&(" + _W_objectClass + "=" + _W_olcDatabaseConfig + ")(" + _W_objectClass + "=" + _W_olcMdbConfig + "))"
	_W_objectClass_posixAccount                                  = "(" + _W_objectClass + "=" + _W_posixAccount + ")"
	_W_objectClass_posixGroup                                    = "(" + _W_objectClass + "=" + _W_posixGroup + ")"
	_W_olc                                                    _W = "olc"
	_W_olcDatabaseConfig                                         = _W_olc + _W_Database + _W_Config
	_W_olcMdbConfig                                              = _W_olc + "Mdb" + _W_Config
	_W_olcSuffix                                                 = _W_olc + "Suffix"
	_W_options                                                _W = "options"
	_W_or                                                     _W = "or"
	_W_orlonger                                                  = _W_or + _W_longer
	_W_ospf                                                   _W = "ospf"
	_W_ou                                                     _W = "ou"
	_W_owner                                                  _W = "owner"
	_W_packet                                                 _W = "packet"
	_W_per                                                    _W = "per"
	_W_per__packet                                               = _W_per + "-" + _W_packet
	_W_permit                                                 _W = "permit"
	_W_permit__all                                               = _W_permit + "-" + _W_all
	_W_pim                                                    _W = "pim"
	_W_ping                                                   _W = "ping"
	_W_policies                                               _W = "policies"
	_W_policy                                                 _W = "policy"
	_W_policy__options                                           = _W_policy + "-" + _W_options
	_W_policy__options___policy__statement                       = _W_policy__options + " " + _W_policy__statement
	_W_policy__options___prefix__list                            = _W_policy__options + " " + _W_prefix__list
	_W_policy__statement                                         = _W_policy + "-" + _W_statement
	_W_pool                                                   _W = "pool"
	_W_port                                                   _W = "port"
	_W_posixAccount                                           _W = "posixAccount"
	_W_posixGroup                                             _W = "posixGroup"
	_W_preference                                             _W = "preference"
	_W_prefix                                                 _W = "prefix"
	_W_prefix__list                                              = _W_prefix + "-" + _W_list
	_W_prefix__list__filter                                      = _W_prefix__list + "-" + _W_filter
	_W_prefix__name                                              = _W_prefix + "-" + _W_name
	_W_protocol                                               _W = "protocol"
	_W_protocols                                                 = _W_protocol + "s"
	_W_protocols___bgp                                           = _W_protocols + " " + _W_bgp
	_W_proxy                                                  _W = "proxy"
	_W_proxy__arp                                                = _W_proxy + "-" + _W_arp
	_W_ptmp                                                   _W = "ptmp"
	_W_ptp                                                    _W = "ptp"
	_W_qnh                                                    _W = "qnh"
	_W_qualified                                              _W = "qualified"
	_W_qualified__next__hop                                      = _W_qualified + "-" + _W_next__hop
	_W_redistribute                                           _W = "redistribute"
	_W_reject                                                 _W = "reject"
	_W_route                                                  _W = "route"
	_W_route__type                                               = _W_route + "-" + _W_type
	_W_routing                                                _W = "routing"
	_W_routing__group                                            = _W_routing + "-" + _W_group
	_W_routing__instance                                         = _W_routing + "-" + _W_instance
	_W_routing__instances                                        = _W_routing__instance + "s"
	_W_rsvp                                                   _W = "rsvp"
	_W_rule                                                   _W = "rule"
	_W_rule__set                                                 = _W_rule + "-" + _W_set
	_W_sctp                                                   _W = "sctp"
	_W_security                                               _W = "security"
	_W_security___address__book                                  = _W_security + " " + _W_address__book
	_W_security___address__book___global                         = _W_security___address__book + " " + _W_global
	_W_security___address__book___global___address               = _W_security___address__book___global + " " + _W_address
	_W_security___address__book___global___address__set          = _W_security___address__book___global + " " + _W_address__set
	_W_security___nat                                            = _W_security + " " + _W_nat
	_W_security___nat___destination                              = _W_security___nat + " " + _W_destination
	_W_security___nat___proxy__arp                               = _W_security___nat + " " + _W_proxy__arp
	_W_security___nat___source                                   = _W_security___nat + " " + _W_source
	_W_security___nat___static                                   = _W_security___nat + " " + _W_static
	_W_security___policies                                       = _W_security + " " + _W_policies
	_W_security___policies___global                              = _W_security___policies + " " + _W_global
	_W_security___policies___global___policy                     = _W_security___policies___global + " " + _W_policy
	_W_security___policy                                         = _W_security + " " + _W_policy
	_W_security__zone                                            = _W_security + "-" + _W_zone
	_W_security__zones                                           = _W_security__zone + "s"
	_W_security__zones___security__zone                          = _W_security__zones + " " + _W_security__zone
	_W_self                                                   _W = "self"
	_W_service                                                _W = "service"
	_W_set                                                    _W = "set"
	_W_sn                                                     _W = "sn"
	_W_snmp                                                   _W = "snmp"
	_W_snmp__trap                                                = _W_snmp + "-" + _W_trap
	_W_source                                                 _W = "source"
	_W_source__address                                           = _W_source + "-" + _W_address
	_W_source__address__name                                     = _W_source__address + "-" + _W_name
	_W_source__nat                                               = _W_source + "-" + _W_nat
	_W_source__port                                              = _W_source + "-" + _W_port
	_W_source__prefix__list                                      = _W_source + "-" + _W_prefix__list
	_W_ssh                                                    _W = "ssh"
	_W_st                                                     _W = "st"
	_W_st0                                                       = _W_st + "0"
	_W_statement                                              _W = "statement"
	_W_static                                                 _W = "static"
	_W_static___route                                            = _W_static + " " + _W_route
	_W_static__nat                                               = _W_static + "-" + _W_nat
	_W_table                                                  _W = "table"
	_W_tcp                                                    _W = "tcp"
	_W_template                                               _W = "template"
	_W_term                                                   _W = "term"
	_W_then                                                   _W = "then"
	_W_to                                                     _W = "to"
	_W_to___routing__instance                                    = _W_to + " " + _W_routing__instance
	_W_to___zone                                                 = _W_to + " " + _W_zone
	_W_to__zone                                                  = _W_to + "-" + _W_zone
	_W_trace                                                  _W = "trace"
	_W_traceroute                                                = _W_trace + _W_route
	_W_traffic                                                _W = "traffic"
	_W_trap                                                   _W = "trap"
	_W_type                                                   _W = "type"
	_W_udp                                                    _W = "udp"
	_W_uid                                                    _W = "uid"
	_W_v4                                                     _W = "v4"
	_W_v6                                                     _W = "v6"
	_W_vi                                                     _W = "vi"
	_W_zone                                                   _W = "zone"
	_W_zones                                                     = _W_zone + "s"
)

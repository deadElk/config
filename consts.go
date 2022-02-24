package main

import (
	log "github.com/sirupsen/logrus"
)

const (
	_loglevel_                                              = log.InfoLevel
	_service                              string            = "config"
	_serviced                                               = _service /*+ "d"*/
	_SERVICE                              string            = "CONFIG"
	_SERVICED                                               = _SERVICE /*+ "D"*/
	_hash_Size                            int               = 512 / 8
	_passwd_Z                             string            = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_passwd_z                             string            = "abcdefghijklmnopqrstuvwxyz"
	_passwd_0                             string            = "0123456789"
	_passwd_oops                          string            = "_" // carefully with special symbols
	_passwd                                                 = _passwd_Z + _passwd_z + _passwd_0 + _passwd_oops
	_vi_ipprefix_                         string            = "10.90.0.0/16"
	_juniper_RI_                          _RI_Name          = "master"
	_juniper_mgmt_RI                      _RI_Name          = "mgmt_junos"
	_juniper_mgmt_IF                      _IF_Name          = "fxp0.0"
	_juniper_mgmt_Description             _Description      = "MANAGEMENT-INSTANCE"
	_gw_hop                               _GW_Type          = "hop"
	_gw_interface                         _GW_Type          = "interface"
	_gw_table                             _GW_Type          = "table"
	_gw_discard                           _GW_Type          = "discard"
	_vi_st                                _VI_Type          = "st"
	_vi_gr                                _VI_Type          = "gr"
	_vi_lt                                _VI_Type          = "lt"
	_vi_                                                    = _vi_st
	_if_comm_ptp                          _IF_Communication = "ptp"
	_if_comm_ptmp                         _IF_Communication = "ptmp"
	_vi_comm_                                               = _if_comm_ptp
	_if_comm_                                               = _if_comm_ptmp
	_if_mode_vi                           _IF_Mode          = "vi"
	_if_mode_link                         _IF_Mode          = "link"
	_rm_bits                              uint              = 2
	_rm_max                                                 = 32/_rm_bits - 1
	_service_all                          _Service          = "all"
	_service_any_service                  _Service          = "any-service"
	_service_bootp                        _Service          = "bootp"
	_service_dhcp                         _Service          = "dhcp"
	_service_dhcpv6                       _Service          = "dhcpv6"
	_service_ike                          _Service          = "ike"
	_service_ping                         _Service          = "ping"
	_service_snmp                         _Service          = "snmp"
	_service_snmp_trap                    _Service          = "snmp-trap"
	_service_ssh                          _Service          = "ssh"
	_service_traceroute                   _Service          = "traceroute"
	_protocol_all                         _Protocol         = "all"
	_protocol_bgp                         _Protocol         = "bgp"
	_AB_Type_set                          _AB_Type          = "set"
	_AB_Type_ipprefix                     _AB_Type          = "ipprefix"
	_AB_Type_fqdn                         _AB_Type          = "fqdn"
	_SP_Type_permit                       _SP_Type          = "permit-all"
	_SP_Type_deny                         _SP_Type          = "deny-all"
	_SP_Type_                                               = _SP_Type_permit
	_PO_PS_Protocol_direct                _PO_PS_Protocol   = "direct"
	_PO_PS_Protocol_aggregate             _PO_PS_Protocol   = "aggregate"
	_PO_PS_Protocol_static                _PO_PS_Protocol   = "static"
	_PO_PS_Protocol_local                 _PO_PS_Protocol   = "local"
	_PO_PS_Protocol_access_internal       _PO_PS_Protocol   = "access-internal"
	_PO_PS_Measure_exact                  _PO_PS_Measure    = "exact"
	_PO_PS_Measure_longer                 _PO_PS_Measure    = "longer"
	_PO_PS_Measure_orlonger               _PO_PS_Measure    = "orlonger"
	_PO_PS_Action_reject                  _PO_PS_Action     = "reject"
	_PO_PS_Action_next_policy             _PO_PS_Action     = "next policy"
	_PO_PS_Action_load_balance_per_packet _PO_PS_Action     = "load-balance per-packet"
)

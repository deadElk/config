package main

import (
	log "github.com/sirupsen/logrus"
)

const (
	_loglevel_          = log.InfoLevel
	_service     string = "config"
	_serviced           = _service /*+ "d"*/
	_SERVICE     string = "CONFIG"
	_SERVICED           = _SERVICE /*+ "D"*/
	_hash_Size   int    = 512 / 8
	_passwd_Z    string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_passwd_z    string = "abcdefghijklmnopqrstuvwxyz"
	_passwd_0    string = "0123456789"
	_passwd_oops string = "_" // carefully with special symbols
	_passwd             = _passwd_Z + _passwd_z + _passwd_0 + _passwd_oops

	_juniper_RI_              _Name          = "master"
	_juniper_mgmt_RI          _Name          = "mgmt_junos"
	_juniper_mgmt_Description _Description   = "MANAGEMENT-INSTANCE"
	_vi_st                    _Type          = "st"
	_vi_gr                    _Type          = "gr"
	_vi_lt                    _Type          = "lt"
	_vi_                                     = _vi_st
	_if_comm_ptp              _Communication = "ptp"
	_if_comm_ptmp             _Communication = "ptmp"
	_vi_comm_                                = _if_comm_ptp
	_if_comm_                                = _if_comm_ptmp
	_if_mode_vi               _Mode          = "vi"
	_if_mode_link             _Mode          = "link"
	_rm_bits                  uint           = 2
	_rm_max                                  = 32/_rm_bits - 1
	_service_ike              _Service       = "ike"
	_service_ping             _Service       = "ping"
	_service_ssh              _Service       = "ssh"
	_service_traceroute       _Service       = "traceroute"
	_protocol_bgp             _Protocol      = "bgp"
	_AB_Type_set              _Type          = "set"
	_AB_Type_ipprefix         _Type          = "ipprefix"
	_AB_Type_fqdn             _Type          = "fqdn"
	_SP_Type_permit           _Type          = "permit-all"

	_Action_hop                     _Action   = "hop"
	_Action_next_hop                _Action   = "next-hop"
	_Action_qnh                     _Action   = "qnh"
	_Action_qualified_next_hop      _Action   = "qualified-next-hop"
	_Action_next_table              _Action   = "next-table"
	_Action_interface               _Action   = "interface"
	_Action_table                   _Action   = "table"
	_Action_discard                 _Action   = "discard"
	_Action_permit_all              _Action   = "permit-all"
	_Action_deny_all                _Action   = "deny-all"
	_Action_permit                  _Action   = "permit"
	_Action_deny                    _Action   = "deny"
	_Action_log                     _Action   = "log"
	_Action_source_nat              _Action   = "source-nat"
	_Action_destination_nat         _Action   = "destination-nat"
	_Action_static_nat              _Action   = "static-nat"
	_Action_reject                  _Action   = "reject"
	_Action_next_policy             _Action   = "next policy"
	_Action_load_balance_per_packet _Action   = "load-balance per-packet"
	_Protocol_direct                _Protocol = "direct"
	_Protocol_aggregate             _Protocol = "aggregate"
	_Protocol_static                _Protocol = "static"
	_Protocol_local                 _Protocol = "local"
	_Protocol_access_internal       _Protocol = "access-internal"
	_Protocol_all                   _Protocol = "all"
	_Protocol_bgp                   _Protocol = "bgp"
	_Type_set                       _Type     = "set"
	_Type_ipprefix                  _Type     = "ipprefix"
	_Type_fqdn                      _Type     = "fqdn"
	_Type_st                        _Type     = "st"
	_Type_gr                        _Type     = "gr"
	_Type_lt                        _Type     = "lt"
	_Type_ptp                       _Type     = "ptp"
	_Type_ptmp                      _Type     = "ptmp"
	_Type_link                      _Type     = "link"
	_Type_vi                        _Type     = "vi"
	_Service_all                    _Service  = "all"
	_Service_any_service            _Service  = "any-service"
	_Service_bootp                  _Service  = "bootp"
	_Service_dhcp                   _Service  = "dhcp"
	_Service_dhcpv6                 _Service  = "dhcpv6"
	_Service_ike                    _Service  = "ike"
	_Service_ping                   _Service  = "ping"
	_Service_snmp                   _Service  = "snmp"
	_Service_snmp_trap              _Service  = "snmp-trap"
	_Service_ssh                    _Service  = "ssh"
	_Service_traceroute             _Service  = "traceroute"
	_Mask_exact                     _Mask     = "exact"
	_Mask_longer                    _Mask     = "longer"
	_Mask_orlonger                  _Mask     = "orlonger"

	_comm_if          _Default = "default_comm_if"
	_comm_vi          _Default = "default_comm_vi"
	_RI               _Default = "default_RI"
	_mgmt_RI          _Default = "default_mgmt_RI"
	_mgmt_IF          _Default = "default_mgmt_IF"
	_mgmt_Description _Default = "default_mgmt_Description"
	_VI_IPPrefix      _Default = "default_VI_IPprefix"
	_VI_IPShift       _Default = "default_VI_IPshift"
	_path_GT          _Default = "default_path_GT"
	_path_out         _Default = "default_path_out"
	_files_config     _Default = "default_files_config"
	_domain_name      _Default = "default_domain_name"
)

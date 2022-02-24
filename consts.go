package main

import (
	"net/netip"

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
	_SP_Action_permit                     _SP_Action        = "permit"
	_SP_Action_deny                       _SP_Action        = "deny"
	_SP_Action_log                        _SP_Action        = "log"
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
	_NAT_Action_source_nat                _NAT_Action       = "source-nat"
	_NAT_Action_destination_nat           _NAT_Action       = "destination-nat"
	_NAT_Action_static_nat                _NAT_Action       = "static-nat"

	_Action_hop                     _Action   = "hop"
	_Action_next_hop                _Action   = "next-hop"
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

	_comm_if          _Default = "default_comm_if"
	_comm_vi          _Default = "default_comm_vi"
	_RI               _Default = "default_RI"
	_mgmt_RI          _Default = "default_mgmt_RI"
	_mgmt_IF          _Default = "default_mgmt_IF"
	_mgmt_Description _Default = "default_mgmt_Description"
	_VI_IPPrefix      _Default = "default_VI_IPprefix"
)

var (
	_Commands = map[interface{}]interface{}{
		_Action_hop:                     _Action_next_hop,
		_Action_interface:               _Action_next_hop,
		_Action_table:                   _Action_next_table,
		_Action_discard:                 _Action_discard,
		_Action_permit_all:              _Action_permit_all,
		_Action_deny_all:                _Action_deny_all,
		_Action_permit:                  _Action_permit,
		_Action_deny:                    _Action_deny,
		_Action_log:                     _Action_log,
		_Action_source_nat:              _Action_source_nat,
		_Action_destination_nat:         _Action_destination_nat,
		_Action_static_nat:              _Action_static_nat,
		_Action_reject:                  _Action_reject,
		_Action_next_policy:             _Action_next_policy,
		_Action_load_balance_per_packet: _Action_load_balance_per_packet,
		_Protocol_direct:                _Protocol_direct,
		_Protocol_aggregate:             _Protocol_aggregate,
		_Protocol_static:                _Protocol_static,
		_Protocol_local:                 _Protocol_local,
		_Protocol_access_internal:       _Protocol_access_internal,
		_Protocol_all:                   _Protocol_all,
		_Protocol_bgp:                   _Protocol_bgp,
		_Type_set:                       _Type_set,
		_Type_ipprefix:                  _Type_ipprefix,
		_Type_fqdn:                      _Type_fqdn,
		_Type_st:                        _Type_st + "0",
		_Type_gr:                        _Type_gr + "0",
		_Type_lt:                        _Type_lt + "0",
		_Type_ptp:                       _Type_ptp,
		_Type_ptmp:                      _Type_ptmp,
		_Type_link:                      _Type_link,
		_Type_vi:                        _Type_vi,
		_Service_all:                    _Service_all,
		_Service_any_service:            _Service_any_service,
		_Service_bootp:                  _Service_bootp,
		_Service_dhcp:                   _Service_dhcp,
		_Service_dhcpv6:                 _Service_dhcpv6,
		_Service_ike:                    _Service_ike,
		_Service_ping:                   _Service_ping,
		_Service_snmp:                   _Service_snmp,
		_Service_snmp_trap:              _Service_snmp_trap,
		_Service_ssh:                    _Service_ssh,
		_Service_traceroute:             _Service_traceroute,
	}
	_Defaults = map[interface{}]interface{}{
		_comm_if:          _Type_ptmp,
		_comm_vi:          _Type_ptp,
		_VI_IPPrefix:      netip.ParsePrefix("10.90.0.0/16"),
		_RI:               _RI_Name("master"),
		_mgmt_RI:          _RI_Name("mgmt_junos"),
		_mgmt_IF:          _IF_Name("fxp0.0"),
		_mgmt_Description: _Description("MANAGEMENT-INSTANCE"),
	}
)

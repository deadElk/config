package main

import (
	"net/netip"
	"regexp"
	"sync"
	"text/template"

	log "github.com/sirupsen/logrus"
)

var (
	hash_cache sync.Map
	re_caps    = regexp.MustCompile(`[A-Z]`)
	re_dot     = regexp.MustCompile(`\.`)
	re_period  = regexp.MustCompile(`,`)
	gt_fm      = template.FuncMap{
		// "sum_uint32": sum_uint32_gt_fm,
		"sum_string": sum_string_gt_fm,
	}
	pdb_ab   = make(map[_Name]_Security_AB)
	pdb_appl = make(map[_Name][]_Security_Application_Term)
	pdb_peer = make(map[_ASN]pDB_Peer)
	pdb_gt   = make(map[_Name]pDB_GT)

	config    = make(_i_config)
	i_ab      = make(_i_ab)
	i_ja      = make(_i_ja)
	i_pl      = make(_i_pl)
	i_ps      = make(_i_ps)
	i_vi      = make(_i_vi)
	i_vi_peer = make(_i_vi_peer)
	i_peer    = make(_i_peer)
	i_gt      = make(_i_gt)
)

var (
	c_Action = map[_Action]_Action{
		_Action_accept:             _Action_accept,
		_Action_add:                _Action_add,
		_Action_deny:               _Action_deny,
		_Action_deny_all:           _Action_deny_all,
		_Action_destination_nat:    _Action_destination_nat,
		_Action_discard:            _Action_discard,
		_Action_hop:                _Action_next_hop,
		_Action_interface:          _Action_next_hop,
		_Action_load_balance:       _Action_load_balance,
		_Action_log:                _Action_log,
		_Action_metric:             _Action_metric,
		_Action_next:               _Action_next,
		_Action_next_hop:           _Action_next_hop,
		_Action_next_table:         _Action_next_table,
		_Action_per_packet:         _Action_per_packet,
		_Action_permit:             _Action_permit,
		_Action_permit_all:         _Action_permit_all,
		_Action_policy:             _Action_policy,
		_Action_qnh:                _Action_qualified_next_hop,
		_Action_qualified_next_hop: _Action_qualified_next_hop,
		_Action_reject:             _Action_reject,
		_Action_self:               _Action_self,
		_Action_source_nat:         _Action_source_nat,
		_Action_static_nat:         _Action_static_nat,
		_Action_table:              _Action_next_table,
		_Action_import:             _Action_import,
		_Action_export:             _Action_export,
	}
	c_Communication = map[_Communication]_Communication{
		_Communication_ptmp: _Communication_ptmp,
		_Communication_ptp:  _Communication_ptp,
	}
	c_Mask = map[_Mask]_Mask{
		_Mask_exact:    _Mask_exact,
		_Mask_longer:   _Mask_longer,
		_Mask_orlonger: _Mask_orlonger,
	}
	c_Protocol = map[_Protocol]_Protocol{
		_Protocol_access_internal: _Protocol_access_internal,
		_Protocol_aggregate:       _Protocol_aggregate,
		_Protocol_all:             _Protocol_all,
		_Protocol_bgp:             _Protocol_bgp,
		_Protocol_direct:          _Protocol_direct,
		_Protocol_local:           _Protocol_local,
		_Protocol_static:          _Protocol_static,
	}
	c_Service = map[_Service]_Service{
		_Service_all:         _Service_all,
		_Service_any_service: _Service_any_service,
		_Service_bootp:       _Service_bootp,
		_Service_dhcp:        _Service_dhcp,
		_Service_dhcpv6:      _Service_dhcpv6,
		_Service_ike:         _Service_ike,
		_Service_ping:        _Service_ping,
		_Service_snmp:        _Service_snmp,
		_Service_snmp_trap:   _Service_snmp_trap,
		_Service_ssh:         _Service_ssh,
		_Service_traceroute:  _Service_traceroute,
	}
	c_Type = map[_Type]_Type{
		_Type_destination:      _Type_destination,
		_Type_fqdn:             _Type_fqdn,
		_Type_from:             _Type_from,
		_Type_gr:               _Type_gr + "0",
		_Type_interface:        _Type_interface,
		_Type_ipprefix:         _Type_ipprefix,
		_Type_link:             _Type_link,
		_Type_lt:               _Type_lt + "0",
		_Type_routing_group:    _Type_routing_group,
		_Type_routing_instance: _Type_routing_instance,
		_Type_security_zone:    _Type_security_zone,
		_Type_set:              _Type_set,
		_Type_source:           _Type_source,
		_Type_st:               _Type_st + "0",
		_Type_static:           _Type_static,
		_Type_to:               _Type_to,
		_Type_vi:               _Type_vi,
		_Type_zone:             _Type_zone,
	}
	_Defaults = map[interface{}]interface{}{
		_loglevel:         log.InfoLevel,
		_sp_efault_policy: _Action_permit_all,
		_comm_if:          _Communication_ptmp,
		_comm_vi:          _Communication_ptp,
		_VI_IPPrefix:      parse_interface(netip.ParsePrefix("10.90.0.0/16")).(netip.Prefix),
		_VI_IPShift:       uint32(0),
		_RI:               _Name("master"),
		_mgmt_RI:          _Name("mgmt_junos"),
		_mgmt_IF:          _Name("fxp0.0"),
		_mgmt_Description: _Description("MANAGEMENT-INSTANCE"),
		_domain_name:      _FQDN("example.com"),
		_ps_bits_per_rm:   uint32(2),        // ____
		_ps_max_rms:       uint32(32/2 - 1), // ^^^^
		_GT_list:          []_Name{},
		_path_GT:          "./templates",
		_path_out:         "./tmp",
		_file_list_config: []string{
			"./" + _serviced + ".xml",
			"/usr/local/opt/etc/" + _serviced + ".xml",
			"/opt/etc/" + _serviced + ".xml",
			"/usr/local/etc/" + _serviced + ".xml",
			"/etc/" + _serviced + ".xml",
		},
	}
)

package main

import (
	"net/netip"
	"regexp"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	hash_cache sync.Map
	re_caps    = regexp.MustCompile(`[A-Z]`)
	re_dot     = regexp.MustCompile(`\.`)
	re_period  = regexp.MustCompile(`,`)
	// gt_fm      = template.FuncMap{
	// 	// "sum_uint32": sum_uint32_gt_fm,
	// 	"sum_string": sum_string_gt_fm,
	// }

	// empty_Name _Name = ""
	empty_Name = _next_IDName
	empty_ID   = _next_ID
	next_ID    = empty_ID

	config      = make(_i_config)
	i_ab        = make(_i_ab)
	i_ja        = make(_i_ja)
	i_pl        = make(_i_pl)
	i_ps        = make(_i_ps)
	i_vi        = make(_i_vi)
	i_vi_peer   = make(_i_vi_peer)
	i_peer      = make(_i_peer)
	i_gt        = make(_i_gt)
	i_ldap      = make(_i_ldap)
	i_read_file = _i_file_data{
		_S_Dir_List[_dir_list_etc]: {ext: "xml", data: map[_Name][]byte{}},
		_S_Dir_List[_dir_list_GT]:  {ext: "tmpl", data: map[_Name][]byte{}},
	}
	i_write_file = _i_file_data{
		_S_Dir_List[_dir_list_Config]: {ext: "txt", data: map[_Name][]byte{}},
		_S_Dir_List[_dir_list_PKI]:    {ext: "", data: map[_Name][]byte{}},
		_S_Dir_List[_dir_list_Portal]: {ext: "", data: map[_Name][]byte{}},
		_S_Dir_List[_dir_list_Data]:   {ext: "xml", data: map[_Name][]byte{}},
	}
)

var (
	c_RO_GW_Action = map[_W]_W{
		_W_discard:              _W_discard,
		_W_interface:            _W_next__hop,
		_W_next__hop:            _W_next__hop,
		_W_next__table:          _W_next__table,
		_W_qnh:                  _W_qualified__next__hop,
		_W_qualified__next__hop: _W_qualified__next__hop,
		_W_table:                _W_next__table,
	}
	// c_Communication = map[_Communication]_Communication{
	// 	_Communication_ptmp: _Communication_ptmp,
	// 	_Communication_ptp:  _Communication_ptp,
	// }
	// c_Mask = map[_Mask]_Mask{
	// 	_Mask_exact:    _Mask_exact,
	// 	_Mask_longer:   _Mask_longer,
	// 	_Mask_orlonger: _Mask_orlonger,
	// }
	// c_Name = map[_Name]_Name{
	// 	_Name_any:        _Name_any,
	// 	_Name_fxp0:       _Name_fxp0,
	// 	_Name_fxp0_0:     _Name_fxp0_0,
	// 	_Name_gr0:        _Name_gr0,
	// 	_Name_junos__host: _Name_junos__host,
	// 	_Name_lo0:        _Name_lo0,
	// 	_Name_lo0_0:      _Name_lo0_0,
	// 	_Name_lt0:        _Name_lt0,
	// 	_Name_master:     _Name_master,
	// 	_Name_mgmt__junos: _Name_mgmt__junos,
	// 	_Name_st0:        _Name_st0,
	// }
	// c_Protocol = map[_Protocol]_Protocol{
	// 	_Protocol_access__internal: _Protocol_access__internal,
	// 	_Protocol_aggregate:       _Protocol_aggregate,
	// 	_Protocol_ah:              _Protocol_ah,
	// 	_Protocol_all:             _Protocol_all,
	// 	_Protocol_bgp:             _Protocol_bgp,
	// 	_Protocol_direct:          _Protocol_direct,
	// 	_Protocol_egp:             _Protocol_egp,
	// 	_Protocol_esp:             _Protocol_esp,
	// 	_Protocol_gre:             _Protocol_gre,
	// 	_Protocol_icmp6:           _Protocol_icmp6,
	// 	_Protocol_icmp:            _Protocol_icmp,
	// 	_Protocol_igmp:            _Protocol_igmp,
	// 	_Protocol_ipip:            _Protocol_ipip,
	// 	_Protocol_local:           _Protocol_local,
	// 	_Protocol_ospf:            _Protocol_ospf,
	// 	_Protocol_pim:             _Protocol_pim,
	// 	_Protocol_rsvp:            _Protocol_rsvp,
	// 	_Protocol_sctp:            _Protocol_sctp,
	// 	_Protocol_static:          _Protocol_static,
	// 	_Protocol_tcp:             _Protocol_tcp,
	// 	_Protocol_udp:             _Protocol_udp,
	// }
	// c_Service = map[_Service]_Service{
	// 	_Service_all:         _Service_all,
	// 	_Service_any__service: _Service_any__service,
	// 	_Service_bootp:       _Service_bootp,
	// 	_Service_dhcp:        _Service_dhcp,
	// 	_Service_dhcpv6:      _Service_dhcpv6,
	// 	_Service_ike:         _Service_ike,
	// 	_Service_ping:        _Service_ping,
	// 	_Service_snmp:        _Service_snmp,
	// 	_Service_snmp_trap:   _Service_snmp_trap,
	// 	_Service_ssh:         _Service_ssh,
	// 	_Service_traceroute:  _Service_traceroute,
	// }
	// c_Type = map[_Type]_Type{
	// 	_Type_destination:      _Type_destination,
	// 	_Type_exact:            _Type_exact,
	// 	_Type_firewall:         _Type_firewall,
	// 	_Type_fqdn:             _Type_fqdn,
	// 	_Type_from:             _Type_from,
	// 	_Type_fxp:              _Type_fxp,
	// 	_Type_global:           _Type_global,
	// 	_Type_gr:               _Type_gr,
	// 	_Type_ipprefix:         _Type_ipprefix,
	// 	_Type_lt:               _Type_lt,
	// 	_Type_lo:               _Type_lo,
	// 	_Type_policy__statement: _Type_policy__statement,
	// 	_Type_pool:             _Type_pool,
	// 	_Type_set:              _Type_set,
	// 	_Type_source:           _Type_source,
	// 	_Type_st:               _Type_st,
	// 	_Type_static:           _Type_static,
	// 	_Type_then:             _Type_then,
	// 	_Type_to:               _Type_to,
	// }
	// _Settings = map[_S]interface{}{
	// 	_group:              _Name("4200000000"),
	// 	_loglevel:           log.InfoLevel,
	// 	_sp_default_policy:  _W_permit__all,
	// 	_comm_if:            _Communication_ptmp,
	// 	_comm_vi:            _Communication_ptp,
	// 	_VI_IPPrefix:        parse_interface(netip.ParsePrefix("10.90.0.0/16")).(netip.Prefix),
	// 	_VI_IPShift:         uint32(0),
	// 	_RI:                 _Name_master,
	// 	_mgmt_RI:            _Name_mgmt__junos,
	// 	_mgmt_IF:            _Name_fxp0_0,
	// 	_host_RI:            _Name_junos__host,
	// 	_mgmt_Description:   _Description("MANAGEMENT-INSTANCE"),
	// 	_domain_name:        _FQDN("example.com"),
	// 	_GT_list:            []_Name{},
	// 	_dir_list_etc:       _Name("etc"),
	// 	_dir_list_GT:        _Name("tmp/templates"),
	// 	_dir_list_Config:    _Name("tmp/CONFIG"),
	// 	_dir_list_PKI:       _Name("tmp/PKI"),
	// 	_dir_list_Portal:    _Name("tmp/portal"),
	// 	_dir_list_Data:      _Name("tmp/data"),
	// 	_filename_host_list: "host_list.txt",
	// 	_filename_config:    "config.xml",
	// 	_filename_list_config: []string{
	// 		"./" + _serviced + ".xml",
	// 		"/usr/local/opt/etc/" + _serviced + ".xml",
	// 		"/opt/etc/" + _serviced + ".xml",
	// 		"/usr/local/etc/" + _serviced + ".xml",
	// 		"/etc/" + _serviced + ".xml",
	// 	},
	// 	// _Route_Weight_bits_per_rm:     _Route_Weight(2),        // ____
	// 	// _Route_Weight_max_rm:         _Route_Weight(32/2 - 1), // ^^^^
	// }
	_S_Dir_List = map[_S]_Name{
		_dir_list_etc:    "etc",
		_dir_list_GT:     "tmp/templates",
		_dir_list_Config: "tmp/CONFIG",
		_dir_list_PKI:    "tmp/PKI",
		_dir_list_Portal: "tmp/portal",
		_dir_list_Data:   "tmp/data",
	}
	_S_Comm = map[_S]_Communication{
		_comm_if: _Communication_ptmp,
		_comm_vi: _Communication_ptp,
	}
	_S_group             _Name        = "4200000000"
	_S_loglevel                       = log.InfoLevel
	_S_sp_default_policy              = _W_permit__all
	_S_VI_IPPrefix                    = parse_interface(netip.ParsePrefix("10.90.0.0/16")).(netip.Prefix)
	_S_VI_IPShift        uint32       = 0
	_S_RI                             = _Name_master
	_S_mgmt_RI                        = _Name_mgmt__junos
	_S_mgmt_IF                        = _Name_fxp0_0
	_S_host_RI                        = _Name_junos__host
	_S_mgmt_Description  _Description = "MANAGEMENT-INSTANCE"
	_S_domain_name       _FQDN        = "example.com"
	_S_GT_list                        = []_Name{}
)

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
	// 	"sum_uint32": sum_uint32_gt_fm,
	// 	"sum_string": sum_string_gt_fm,
	// }

	// empty_Name _Name
	empty_Name = _next_IDName
	empty_ID   = _next_ID
	next_ID    = empty_ID

	i_ab        = make(_i_ab)
	i_ja        = make(_i_ja)
	i_pl        = make(_i_pl)
	i_ps        = make(_i_ps)
	i_vi        = make(_i_vi)
	i_vi_peer   = make(_i_vi_peer)
	i_peer      = make(_i_peer)
	i_ldap      = make(_i_ldap)
	i_read_file = _i_file_data{
		_S_Dir_List[_dir_list_etc]: {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_GT]:  {ext: "tmpl", data: map[_Name]_Content{}},
	}
	i_write_file = _i_file_data{
		_S_Dir_List[_dir_list_Config]: {ext: "txt", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_PKI]:    {ext: "", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_Portal]: {ext: "", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_Data]:   {ext: "xml", data: map[_Name]_Content{}},
	}
	i_peer_list []_ASN

	c_RO_GW_Action = map[_W]_W{
		_W_discard:              _W_discard,
		_W_interface:            _W_next__hop,
		_W_next__hop:            _W_next__hop,
		_W_next__table:          _W_next__table,
		_W_qnh:                  _W_qualified__next__hop,
		_W_qualified__next__hop: _W_qualified__next__hop,
		_W_table:                _W_next__table,
	}
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
	_S_GT_List                        = []_Name{}
)

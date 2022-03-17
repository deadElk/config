package main

import (
	"encoding/binary"
	"net/netip"
	"regexp"
	"sync"
)

var (
	hash_cache    sync.Map
	re_upper_case = regexp.MustCompile(`[A-Z]+`)
	re_lower_case = regexp.MustCompile(`[a-z]+`)
	re_digit      = regexp.MustCompile(`[0-9]+`)
	re_symbol     = regexp.MustCompile(`_+`)
	re_dot        = regexp.MustCompile(`\.+`)
	re_period     = regexp.MustCompile(`,+`)
	// gt_fm      = template.FuncMap{
	// 	"sum_uint32": sum_uint32_gt_fm,
	// 	"sum_string": sum_string_gt_fm,
	// }

	// empty_Name _Name
	empty_Name = _next_IDName
	empty_ID   = _next_ID
	next_ID    = empty_ID

	i_ab         = make(__N_AB)
	i_ja         = make(__N_JA)
	i_pl         = make(__N_PO_PL)
	i_ps         = make(__N_PO_PS)
	i_vi         = make(__i_VI)
	i_vi_peer    = make(__i_VI_ID_Peer)
	i_peer       = make(__A_Peer)
	i_peer_group = make(__A_Peer_Group)
	i_ldap       = make(__U_LDAP)
	i_read_file  = __N_File_Data{
		_S_Dir_List[_dir_list_GT]:  {ext: "tmpl", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_etc]: {ext: "xml", data: map[_Name]_Content{}},
	}
	i_write_file = __N_File_Data{
		_S_Dir_List[_dir_list_Config]: {ext: "txt", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_Data]:   {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_LDAP]:   {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_PKI]:    {ext: "", data: map[_Name]_Content{}},
		_S_Dir_List[_dir_list_Portal]: {ext: "", data: map[_Name]_Content{}},
	}
	i_peer_list []_ASN

	c_VI_Action = map[_Type]_W{
		_Type_gr: _W_gr0,
		_Type_lt: _W_lt0,
		_Type_st: _W_st0,
	}
	c_RO_GW_Action = map[_W]_W{
		_W_discard:              _W_discard,
		_W_interface:            _W_next__hop,
		_W_next__hop:            _W_next__hop,
		_W_next__table:          _W_next__table,
		_W_qnh:                  _W_qualified__next__hop,
		_W_qualified__next__hop: _W_qualified__next__hop,
		_W_table:                _W_next__table,
	}
	_S_Dir_List = map[_ID]_Name{
		_dir_list_Config: "tmp/CONFIG",
		_dir_list_Data:   "tmp/data",
		_dir_list_GT:     "tmp/templates",
		_dir_list_LDAP:   "tmp/LDAP",
		_dir_list_PKI:    "tmp/PKI",
		_dir_list_Portal: "tmp/portal",
		_dir_list_etc:    "etc",
	}
	_S_File_List = map[_ID]_Name{
		_file_host_list: "host_list",
	}
	_S_Comm = map[_ID]_Communication{
		_comm_if: _Communication_ptmp,
		_comm_vi: _Communication_ptp,
	}
	_S_GT_List     []_Name
	_S_VI_IPPrefix = parse_interface(netip.ParsePrefix("10.90.0.0/16")).(netip.Prefix)
	_S_VI_IPShift  = binary.BigEndian.Uint32(_S_VI_IPPrefix.Addr().AsSlice())
)

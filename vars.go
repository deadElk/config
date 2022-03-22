package main

import (
	"math/big"
	"net/netip"
	"regexp"
	"sync"
)

var (
	hash_cache          sync.Map
	re_upper_case       = regexp.MustCompile(`[A-Z]+`)
	re_lower_case       = regexp.MustCompile(`[a-z]+`)
	re_digits           = regexp.MustCompile(`[0-9]+`)
	re_symbols          = regexp.MustCompile(`_+`)
	re_dots             = regexp.MustCompile(`\.+`)
	re_equals           = regexp.MustCompile(`=+`)
	re_commas           = regexp.MustCompile(`,+`)
	re_slashes          = regexp.MustCompile(`/+`)
	re_string_splitters = regexp.MustCompile(`[;, \t]+`)
	// gt_fm      = template.FuncMap{
	// 	"sum_uint32": sum_uint32_gt_fm,
	// 	"sum_string": sum_string_gt_fm,
	// }

	// empty_Name _Name
	empty_Name = _next_IDName
	empty_ID   = _next_ID
	next_ID    = empty_ID

	// daemon's global PKI SerialNumber used for Cert and CRL
	i_PKI_SN      = big.NewInt(0)
	i_PKI         = make(__FQDN_PKI)
	i_ab          = make(__N_AB)
	i_ja          = make(__N_JA)
	i_pl          = make(__N_PO_PL)
	i_ps          = make(__N_PO_PS)
	i_vi          = make(__i_VI)
	i_vi_peer     = make(__i_VI_ID_Peer)
	i_peer        = make(__A_Peer)
	i_peer_group  = make(__A_Peer_Group)
	i_ldap        = make(__U_LDAP)
	i_ldap_domain = make(__DN_LDAP_Domain)
	i_read_file   = __N_File_Data{
		_S_Dir[_dir_GT]:     {ext: "tmpl", data: map[_Name]_Content{}},
		_S_Dir[_dir_etc]:    {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir[_dir_Modify]: {ext: "xml", data: map[_Name]_Content{}},
	}
	i_write_file = __N_File_Data{
		_S_Dir[_dir_Config]: {ext: "txt", data: map[_Name]_Content{}},
		_S_Dir[_dir_Data]:   {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir[_dir_Modify]: {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir[_dir_LDAP]:   {ext: "xml", data: map[_Name]_Content{}},
		_S_Dir[_dir_PKI]:    {ext: "key", data: map[_Name]_Content{}},
		_S_Dir[_dir_Portal]: {ext: "", data: map[_Name]_Content{}},
	}
	i_peer_list []_Inet_ASN
	i_vi_ip     = make(__INet_VI_IP_Table)
	i_ui_ip     = make(__INet_UI_IP_Table)

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
	_S_Dir = map[_ID]_Name{
		_dir_Config: "tmp/CONFIG",
		_dir_Data:   "tmp/data",
		_dir_Modify: "tmp/modify",
		_dir_GT:     "tmp/templates",
		_dir_LDAP:   "tmp/LDAP",
		_dir_PKI:    "tmp/PKI",
		_dir_Portal: "tmp/portal",
		_dir_etc:    "etc",
	}
	_S_File = map[_ID]_Name{
		_file_host_list: "host_list",
	}
	_S_Comm = map[_ID]_Communication{
		_comm_if: _Communication_ptmp,
		_comm_vi: _Communication_ptp,
	}
	_S_GT_List     []_Name
	_S_VI_IPPrefix = parse_interface(
		parse_interface(
			netip.ParseAddr(_VIx_Addr)).(netip.Addr).Prefix(int(_VIx_bits))).(netip.Prefix)
	_S_UI_IPPrefix = parse_interface(
		parse_interface(
			netip.ParseAddr(_UIx_Addr)).(netip.Addr).Prefix(int(_UIx_mask))).(netip.Prefix)
)

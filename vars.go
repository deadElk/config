package main

import (
	"net/netip"
	"regexp"
	"sync"
)

var (
	hash_cache    sync.Map
	hash224_cache sync.Map

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
	// i_PKI         = make(__FQDN_PKI_Domain)
	// i_PKI_SN      = big.NewInt(0) // use big.NewInt(time.Now().Unixnano())
	i_PKI         = &_PKI_CA_Node{CA_Node: __FQDN_PKI_CA_Node{}}
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
	i_file        = __N_File_Data{
		_dir_Config:   {Ext: "txt", File: __N_File_Data_Content{}},
		_dir_Data:     {Ext: "xml", File: __N_File_Data_Content{}},
		_dir_GT:       {Ext: "tmpl", File: __N_File_Data_Content{}},
		_dir_LDAP:     {Ext: "xml", File: __N_File_Data_Content{}},
		_dir_Modify:   {Ext: "xml", File: __N_File_Data_Content{}},
		_dir_PKI:      {Ext: "", File: __N_File_Data_Content{}},
		_dir_PKI_Cert: {Ext: "der", File: __N_File_Data_Content{}},
		_dir_PKI_Key:  {Ext: "der", File: __N_File_Data_Content{}},
		_dir_PKI_CRL:  {Ext: "der", File: __N_File_Data_Content{}},
		_dir_PKI_P12:  {Ext: "p12", File: __N_File_Data_Content{}},
		_dir_Portal:   {Ext: "", File: __N_File_Data_Content{}},
		_dir_etc:      {Ext: "xml", File: __N_File_Data_Content{}},
	}
	i_read_list = __N_File_Data{
		_dir_GT:       i_file[_dir_GT],
		_dir_Modify:   i_file[_dir_Modify],
		_dir_PKI_Cert: i_file[_dir_PKI_Cert],
		_dir_PKI_Key:  i_file[_dir_PKI_Key],
		_dir_PKI_CRL:  i_file[_dir_PKI_CRL],
		_dir_etc:      i_file[_dir_etc],
	}
	i_write_list = __N_File_Data{
		_dir_Config:   i_file[_dir_Config],
		_dir_Data:     i_file[_dir_Data],
		_dir_LDAP:     i_file[_dir_LDAP],
		_dir_Modify:   i_file[_dir_Modify],
		_dir_PKI_Cert: i_file[_dir_PKI_Cert],
		_dir_PKI_Key:  i_file[_dir_PKI_Key],
		_dir_PKI_CRL:  i_file[_dir_PKI_CRL],
		_dir_PKI_P12:  i_file[_dir_PKI_P12],
		_dir_Portal:   i_file[_dir_Portal],
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
	// _S_Dir = map[_ID]_Name{
	// 	_dir_Config:  "tmp/CONFIG",
	// 	_dir_Data:    "tmp/data",
	// 	_dir_GT:      "tmp/templates",
	// 	_dir_LDAP:    "tmp/LDAP",
	// 	_dir_Modify:  "tmp/modify",
	// 	_dir_PKI:     "tmp/PKI",
	// 	_dir_PKI_Key: "tmp/PKI/Key",
	// 	_dir_Portal:  "tmp/portal",
	// 	_dir_etc:     "etc",
	// }
	// _S_File = map[_ID]_Name{
	// 	_file_host_list: "host_list",
	// }
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

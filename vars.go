package main

import (
	"net/netip"
	"regexp"
	"sync"
)

var (
	hash_cache    sync.Map
	hash224_cache sync.Map

	_not_ok bool

	re_upper_case       = regexp.MustCompile(`[A-Z]+`)
	re_lower_case       = regexp.MustCompile(`[a-z]+`)
	re_digits           = regexp.MustCompile(`[0-9]+`)
	re_symbols          = regexp.MustCompile(`_+`)
	re_dots             = regexp.MustCompile(`\.+`)
	re_equals           = regexp.MustCompile(`=+`)
	re_commas           = regexp.MustCompile(`,+`)
	re_spaces           = regexp.MustCompile(` +`)
	re_slashes          = regexp.MustCompile(`/+`)
	re_string_splitters = regexp.MustCompile(`[;, \t\n]+`)
	re_strict_splitters = regexp.MustCompile(`[; \t\n]+`)
	// gt_fm      = template.FuncMap{
	// 	"sum_uint32": sum_uint32_gt_fm,
	// 	"sum_string": sum_string_gt_fm,
	// }

	// empty_Name _Name
	empty_Name = _next_IDName
	empty_ID   = _next_ID
	next_ID    = empty_ID

	i_PKI_Revoke = make(map[_FQDN]bool)
	i_PKI        = &_PKI{
		FQDN: __FQDN_PKI_Container{},
		SN:   __SN_PKI_Container{},
	}
	// i_PKI_FQDN = make(__FQDN_PKI_Container)
	// i_PKI_SN   = make(__SN_PKI_Container)

	// i_PKI_P12 = make(__FQDN_PKI_Container)
	// daemon's global PKI SerialNumber used for Cert and CRL
	// i_PKI_DB         = make(__FQDN_PKI_Domain)
	// i_PKI_SN      = big.NewInt(0) // use big.NewInt(time.Now().Unixnano())
	// i_PKI         = make(__BI_Any)
	// i_PKI_DB      = &_PKI_CA_Node{CA_Node: __FQDN_PKI_CA_Node{}}

	i_ab          = make(__N_AB)
	i_ja          = make(__N_JA)
	i_pl          = make(__N_PO_PL)
	i_ps          = make(__N_PO_PS)
	i_vi          = make(__VI_VI)
	i_vi_peer     = make(__VI__VIC_VI_Peer)
	i_peer        = make(__ASN_Peer)
	i_peer_group  = make(__ASN_Peer_Group)
	i_ldap        = make(__URL_LDAP)
	i_ldap_domain = make(__DN_LDAP_Domain)
	i_file_link   = make(__LN_Link_Name)
	i_file        = __DN_File_Dir{
		_dir_GT:      {Type: _Type_template},
		_dir_GT_OVPN: {Type: _Type_template},
		_dir_PKI_CA:  {},
		_dir_PKI_TLS: {Recursive: true},
		_dir_etc:     {},
		// _dir_Config:         {Ext: "txt"},
		// _dir_Modify:         {Ext: "xml"},
		// _dir_Data:           {Ext: "xml"},
		// _dir_LDAP:           {Ext: "xml"},
		// _dir_PKI_Cert:       {Ext: "p12"},
		// _dir_Portal:         {Ext: ""},
		// _dir_Stage:          {Ext: ""},
		// _dir_Stage_OVPN:     {Ext: ""},
		// _dir_Stage_OVPN_ULE_OVPN: {Ext: ""},
	}

	i_OVPN      = make(map[_FQDN]*_OVPN_GT_Server)
	i_peer_list []_Inet_ASN
	i_vi_ip     = make(__INet_VI_IP_Table)
	i_ui_ip     = make(__INet_UI_IP_Table)
	i_host      = make(__DN_LDAP_Domain_Host)

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

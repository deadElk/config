package main

import (
	"net/netip"
	"regexp"
	"sync"
	"text/template"
)

var (
	hash_cache sync.Map
	re_caps    = regexp.MustCompile(`[A-Z]`)
	re_dot     = regexp.MustCompile(`\.`)
	re_period  = regexp.MustCompile(`,`)
	gt_fm      = template.FuncMap{
		"sum_uint32": sum_uint32_gt_fm,
		"sum_string": sum_string_gt_fm,
	}
	_loglevel = _default_loglevel
	rm_id     = func() (outbound _RM_ID) {
		for shift, interim := 0, 0; interim <= int(_rm_max); interim, shift = interim+1, shift+int(_rm_bits) {
			outbound[interim] = 1 << shift
		}
		return
	}()
	vi_ipprefix netip.Prefix
	vi_ip_shift _VI_ID
	pdb_ab      = make(map[_AB_Name]_AB)
	pdb_appl    = make(map[_Application_Name][]_Application_Term)
	pdb_peer    = make(map[_ASN]pDB_Peer)
	pdb_gt      = make(map[_GT_Name]pDB_GT)
	config      = make(map[_ASN][]byte)
	fs_path     = map[string]string{
		"upload":    "./tmp/",
		"templates": "./templates/",
	}
	domain_name _FQDN
)

package main

import (
	"net/netip"

	log "github.com/sirupsen/logrus"
)

func parse_iDB() (ok bool) {
	// define_iDB_Vocabulary()
	parse_iDB_Peer_Vocabulary()
	return true
}

func parse_iDB_Peer_Vocabulary() (ok bool) {
	for y, v_Peer := range i_peer {

		var (
			interim = make(map[_Name]*i_AB)
		)
		for a := range v_Peer.AB {
			peer_iDB_recurse_AB(&interim, a)
		}
		v_Peer.AB = interim

		for _, b := range v_Peer.PS {
			for _, d := range b.Term {
				for _, f := range d.From {
					v_Peer.link_PL(f.PL)
				}
			}
		}

		i_peer[y] = v_Peer
	}
	return true
}
func peer_iDB_recurse_AB(interim *map[_Name]*i_AB, inbound _Name) (ok bool) {
	(*interim)[inbound] = i_ab[inbound]
	for a, b := range i_ab[inbound].Set {
		switch {
		case b.Type != _Type_set || (*interim)[a] == nil:
			peer_iDB_recurse_AB(interim, a)
		}
	}
	return true
}

func define_iDB_Vocabulary() (ok bool) {
	parse_iDB_AB_create_Set(_Name_PUBLIC, &_Attribute_List{})

	for a, b := range map[_Name][]string{
		"any_v4":       {"0.0.0.0/0"},
		"loopback_v4":  {"127.0.0.0/8"},
		"private_v4":   {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		"linklocal_v4": {"169.254.0.0/16"},
	} {
		parse_iDB_AB_create_Set(a, &_Attribute_List{})
		i_pl[a] = &i_PO_PL{GT_Action: strings_join(" ", _Action_policy__options___prefix__list, a)}
		for _, d := range b {
			var (
				e = parse_interface(netip.ParsePrefix(d)).(netip.Prefix)
			)
			parse_cDB_AB_add_Address_List(true, true, a, e)
			i_pl[a].Match = append(i_pl[a].Match, i_PO_PL_Match{
				IPPrefix:  e,
				GT_Action: d,
			})
		}
		i_ps[_Name(strings_join("_", _Action_aggregate, a))] = &i_PO_PS{
			Term: []i_PO_PS_Term{
				0: {
					Name: "REJECT",
					From: []i_PO_PS_From{
						0: {PL: a, Mask: _Mask_longer, GT_Action: strings_join(" ", _Action_prefix__list__filter, a, _Mask_longer)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_load_balance, Action_Flag: _Action_per__packet, GT_Action: strings_join(" ", _Action_load_balance, _Action_per__packet)},
					},
					GT_Action: strings_join(" ", _Action_term, "REJECT"),
				},
			},
			GT_Action: strings_join(" ", _Action_policy__options___policy__statement, _Name(strings_join("_", _Action_aggregate, a))),
		}
	}

	for a, b := uint32(0), _Route_Weight(1); a <= uint32(_Route_Weight_max_rm); a, b = a+1, b<<int(_Route_Weight_bits_per_rm) {
		var (
			c = _Name(strings_join("_", _Action_import_metric, pad(a, 2)))
			d = _Name(strings_join("_", _Action_export_metric, pad(a, 2)))
		)
		i_ps[c] = &i_PO_PS{
			Term: []i_PO_PS_Term{
				0: {
					Name: "ACCEPT",
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Action_Flag: _Action_add, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, _Action_add, b)},
						1: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "ACCEPT"),
				},
			},
			GT_Action: strings_join(" ", _Action_policy__options___policy__statement, c),
		}
		i_ps[d] = &i_PO_PS{
			Term: []i_PO_PS_Term{
				0: {
					Name: "LOCAL",
					From: []i_PO_PS_From{
						0: {Protocol: _Protocol_access_internal, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_access_internal)},
						1: {Protocol: _Protocol_local, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_local)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_reject, GT_Action: strings_join(" ", _Action_then, _Action_reject)},
					},
					GT_Action: strings_join(" ", _Action_term, "LOCAL"),
				},

				1: {
					Name: "DIRECT",
					From: []i_PO_PS_From{
						0: {Protocol: _Protocol_direct, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_direct)},
						1: {Protocol: _Protocol_static, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_static)},
						2: {Protocol: _Protocol_aggregate, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_aggregate)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, b)},
						1: {Action: _Action_next__hop, Action_Flag: _Action_self, GT_Action: strings_join(" ", _Action_then, _Action_next__hop, _Action_self)},
						2: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "DIRECT"),
				},
				2: {
					Name: "INTERNAL",
					From: []i_PO_PS_From{
						0: {Route_Type: _Type_internal, GT_Action: strings_join(" ", _Action_from, _Action_route__type, _Type_internal)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Action_Flag: _Action_add, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, _Action_add, b+1)},
						1: {Action: _Action_next__hop, Action_Flag: _Action_self, GT_Action: strings_join(" ", _Action_then, _Action_next__hop, _Action_self)},
						2: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "INTERNAL"),
				},
				3: {
					Name: "EXTERNAL",
					From: []i_PO_PS_From{
						0: {Route_Type: _Type_external, GT_Action: strings_join(" ", _Action_from, _Action_route__type, _Type_external)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Action_Flag: _Action_add, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, _Action_add, b)},
						1: {Action: _Action_next__hop, Action_Flag: _Action_self, GT_Action: strings_join(" ", _Action_then, _Action_next__hop, _Action_self)},
						2: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "EXTERNAL"),
				},

				4: {
					Name: "REJECT",
					Then: []i_PO_PS_Then{
						0: {Action: _Action_reject, GT_Action: strings_join(" ", _Action_then, _Action_reject)},
					},
					GT_Action: strings_join(" ", _Action_term, "REJECT"),
				},
			},
			GT_Action: strings_join(" ", _Action_policy__options___policy__statement, d),
		}
	}
	i_ps[_Name(_Action_per__packet)] = &i_PO_PS{
		Term: []i_PO_PS_Term{
			0: {
				Name: "PER_PACKET",
				Then: []i_PO_PS_Then{
					0: {Action: _Action_load_balance, Action_Flag: _Action_per__packet, GT_Action: strings_join(" ", _Action_load_balance, _Action_per__packet)},
				},
				GT_Action: strings_join(" ", _Action_term, "PER_PACKET"),
			},
		},
		GT_Action: strings_join(" ", _Action_policy__options___policy__statement, _Name(_Action_per__packet)),
	}
	return true
}

func netip_Addr_to_Prefix(inbound *netip.Addr) (outbound netip.Prefix) {
	return parse_interface((*inbound).Prefix((*inbound).BitLen())).(netip.Prefix)
}
func parse_iDB_AB_netip_Prefix(public, private bool, ab_name *_Name, inbound *netip.Prefix, interim *map[netip.Prefix]bool) (ok bool) {
	switch _, flag := (*interim)[*inbound]; {
	case flag:
		return
	}
	switch is_private, is_valid := (*inbound).Masked().Addr().IsPrivate(), (*inbound).IsValid(); {
	case !is_valid || (is_private && !private) || (!is_private && !public):
		log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", *ab_name, *inbound, is_valid, public, private)
		return
	}
	return true
}
func parse_iDB_AB_FQDN(public, private bool, ab_name *_Name, inbound *_FQDN, interim *map[_FQDN]bool) (ok bool) {
	switch _, flag := (*interim)[*inbound]; {
	case flag || len(*inbound) == 0:
		return
	}
	return true
}
func parse_iDB_AB_Name(public, private bool, ab_name *_Name, inbound *_Name, interim *map[_Name]bool) (ok bool) {
	switch _, flag := (*interim)[*inbound]; {
	case flag || len(*inbound) == 0:
		return
	}
	return true
}

func parse_iDB_AB_create_Set(ab_name _Name, al *_Attribute_List) (ok bool) {
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:            _Type_set,
		Set:             map[_Name]i_AB_Set{},
		GT_Action:       strings_join(" ", _Action_security___address__book___global___address__set, ab_name),
		_Attribute_List: *al,
	}
	return true
}
func parse_iDB_AB_create_Prefix(inbound *netip.Prefix, al *_Attribute_List) (ok bool) {
	var (
		ab_name = _Name((*inbound).String())
	)
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:            _Type_ipprefix,
		IPPrefix:        *inbound,
		GT_Action:       strings_join(" ", _Action_security___address__book___global___address, ab_name, _Action_address, *inbound),
		_Attribute_List: *al,
	}
	return true
}
func parse_iDB_AB_create_FQDN(inbound *_FQDN, al *_Attribute_List) (ok bool) {
	var (
		ab_name = _Name(*inbound)
	)
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:            _Type_fqdn,
		FQDN:            *inbound,
		GT_Action:       strings_join(" ", _Action_security___address__book___global___address, ab_name, _Action_dns__name, *inbound),
		_Attribute_List: *al,
	}
	return true
}

package main

import (
	"net/netip"
	"sort"

	log "github.com/sirupsen/logrus"
)

func parse_iDB_Vocabulary() {
	for y, v_Peer := range i_peer {

		var (
			interim = make(__N_AB)
		)
		for a := range v_Peer.AB {
			interim.parse_recurse_AB(a)
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
}

func generate_iDB_host_list() {
	i_file.put(_dir_Config, _file_host_list, "\n", "")
	sort.Slice(i_peer_list, func(i, j int) bool {
		return i_peer_list[i] < i_peer_list[j]
	})
	for _, b := range i_peer_list {
		var (
			s_public  *[]_Name
			s_private *[]_Name
			ip_list   = "\t"
			s_target  = []string{0: i_peer[b].Router_ID.String()} // todo: WTF????
		)
		s_private = i_peer[b].AB[_Name(join_string("_", "I", i_peer[b].ASName))].get_address_list(s_private)
		s_public = i_peer[b].AB[_Name(join_string("_", "O", i_peer[b].ASName))].get_address_list(s_public)
		sort.Slice(*s_private, func(i, j int) bool {
			return (*s_private)[i] < (*s_private)[j]
		})
		sort.Slice(*s_public, func(i, j int) bool {
			return (*s_public)[i] < (*s_public)[j]
		})

		for _, d := range *s_private {
			ip_list += tabber(d.String(), 3) + "\t"
		}
		for _, d := range *s_public {
			s_target = append(s_target, d.String())
			ip_list += tabber(d.String(), 3) + "\t"
		}

		for _, f := range s_target {
			var (
				host = func() string {
					switch addr, err := netip.ParseAddr(f); {
					case err == nil:
						return addr.String()
					default:
						prefix, _ := netip.ParsePrefix(f)
						return prefix.Addr().String()
					}
				}()
			)
			i_file.append(_dir_Config, _file_host_list, "\n", tabber(host, 2)+
				"\t####\t"+
				tabber(i_peer[b].PName.String(), 2)+"\t"+
				tabber(i_peer[b].Hostname.String(), 3)+"\t"+
				tabber(i_peer[b].Manufacturer+" "+i_peer[b].Model, 3)+"\t####\t"+
				ip_list)
		}
		i_file.append(_dir_Config, _file_host_list, "", "\n")
	}
}

func define_iDB_Vocabulary() {
	create_iDB_AB_Set(_Name_PUBLIC)

	for a, b := range map[_Name][]string{
		"any_v4":       {"0.0.0.0/0"},
		"loopback_v4":  {"127.0.0.0/8"},
		"private_v4":   {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		"linklocal_v4": {"169.254.0.0/16"},
	} {
		switch {
		case len(b) > 1:
			create_iDB_AB_Set(a)
		}
		i_pl[a] = &i_PO_PL{GT_Action: join_string(" ", _W_policy__options___prefix__list, a)}
		for _, d := range b {
			var (
				e = parse_interface(netip.ParsePrefix(d)).(netip.Prefix)
			)
			add_iDB_AB_Address_List(true, true, a, e)
			i_pl[a].Match = append(i_pl[a].Match, &i_PO_PL_Match{
				IPPrefix:  e,
				GT_Action: d,
			})
		}
		i_ps[_Name(join_string("_", _W_aggregate, a))] = &i_PO_PS{
			Term: __PO_PS_Term{
				0: {
					Name: "REJECT",
					From: __PO_PS_From{
						0: {PL: a, Mask: _Mask_longer, GT_Action: join_string(" ", _W_prefix__list__filter, a, _Mask_longer)},
					},
					Then: __PO_PS_Then{
						0: {Action: _W_load__balance, Action_Flag: _W_per__packet, GT_Action: join_string(" ", _W_load__balance, _W_per__packet)},
					},
					GT_Action: join_string(" ", _W_term, "REJECT"),
				},
			},
			GT_Action: join_string(" ", _W_policy__options___policy__statement, _Name(join_string("_", _W_aggregate, a))),
		}
	}

	for a, b := uint32(0), _INet_Routing(1); a <= uint32(_Route_Weight_max_rm); a, b = a+1, b<<int(_Route_Weight_bits_per_rm) {
		var (
			c = _Name(join_string("_", _W_import_metric, pad_string(a, 2)))
			d = _Name(join_string("_", _W_export_metric, pad_string(a, 2)))
		)
		i_ps[c] = &i_PO_PS{
			Term: __PO_PS_Term{
				0: {
					Name: "ACCEPT",
					Then: __PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, _W_add, b)},
						1: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "ACCEPT"),
				},
			},
			GT_Action: join_string(" ", _W_policy__options___policy__statement, c),
		}
		i_ps[d] = &i_PO_PS{
			Term: __PO_PS_Term{
				0: {
					Name: "LOCAL",
					From: __PO_PS_From{
						0: {Protocol: _Protocol_access_internal, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_access_internal)},
						1: {Protocol: _Protocol_local, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_local)},
					},
					Then: __PO_PS_Then{
						0: {Action: _W_reject, GT_Action: join_string(" ", _W_then, _W_reject)},
					},
					GT_Action: join_string(" ", _W_term, "LOCAL"),
				},

				1: {
					Name: "DIRECT",
					From: __PO_PS_From{
						0: {Protocol: _Protocol_direct, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_direct)},
						1: {Protocol: _Protocol_static, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_static)},
						2: {Protocol: _Protocol_aggregate, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_aggregate)},
					},
					Then: __PO_PS_Then{
						0: {Action: _W_metric, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, b)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: join_string(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "DIRECT"),
				},
				2: {
					Name: "INTERNAL",
					From: __PO_PS_From{
						0: {Route_Type: _Type_internal, GT_Action: join_string(" ", _W_from, _W_route__type, _Type_internal)},
					},
					Then: __PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, _W_add, b+1)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: join_string(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "INTERNAL"),
				},
				3: {
					Name: "EXTERNAL",
					From: __PO_PS_From{
						0: {Route_Type: _Type_external, GT_Action: join_string(" ", _W_from, _W_route__type, _Type_external)},
					},
					Then: __PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, _W_add, b)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: join_string(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "EXTERNAL"),
				},

				4: {
					Name: "REJECT",
					Then: __PO_PS_Then{
						0: {Action: _W_reject, GT_Action: join_string(" ", _W_then, _W_reject)},
					},
					GT_Action: join_string(" ", _W_term, "REJECT"),
				},
			},
			GT_Action: join_string(" ", _W_policy__options___policy__statement, d),
		}
	}
	i_ps[_Name(_W_per__packet)] = &i_PO_PS{
		Term: __PO_PS_Term{
			0: {
				Name: "PER_PACKET",
				Then: __PO_PS_Then{
					0: {Action: _W_load__balance, Action_Flag: _W_per__packet, GT_Action: join_string(" ", _W_load__balance, _W_per__packet)},
				},
				GT_Action: join_string(" ", _W_term, "PER_PACKET"),
			},
		},
		GT_Action: join_string(" ", _W_policy__options___policy__statement, _Name(_W_per__packet)),
	}
}

func parse_iDB_AB_Prefix(public, private bool, ab_name _Name, inbound netip.Prefix, interim map[netip.Prefix]bool) {
	switch _, flag := interim[inbound]; {
	case flag:
		return
	}
	switch is_private, is_valid := inbound.Masked().Addr().IsPrivate(), inbound.IsValid(); {
	case !is_valid || (is_private && !private) || (!is_private && !public):
		log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, inbound, is_valid, public, private)
		return
	}
	interim[inbound] = true
}
func parse_iDB_AB_FQDN(public, private bool, ab_name _Name, inbound _FQDN, interim map[_FQDN]bool) {
	switch _, flag := interim[inbound]; {
	case flag || len(inbound) == 0:
		return
	}
	interim[inbound] = true
}
func parse_iDB_AB_Name(public, private bool, ab_name _Name, inbound _Name, interim map[_Name]bool) {
	switch _, flag := interim[inbound]; {
	case flag || len(inbound) == 0:
		return
	}
	interim[inbound] = true
}

func create_iDB_AB_Set(ab_name _Name) (ok bool) {
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:      _Type_set,
		Set:       __N_AB_Set{},
		GT_Action: join_string(" ", _W_security___address__book___global___address__set, ab_name),
	}
	return true
}
func create_iDB_AB_FQDN(ab_name _Name, inbound _FQDN) (ok bool) {
	switch {
	case len(ab_name) == 0:
		ab_name = _Name(inbound)
	}
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:      _Type_fqdn,
		FQDN:      inbound,
		GT_Action: join_string(" ", _W_security___address__book___global___address, ab_name, _W_dns__name, inbound),
	}
	return true
}
func create_iDB_AB_Prefix(ab_name _Name, inbound netip.Prefix) (ok bool) {
	switch {
	case len(ab_name) == 0:
		ab_name = _Name(inbound.String())
	}
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:      _Type_ipprefix,
		IPPrefix:  inbound,
		GT_Action: join_string(" ", _W_security___address__book___global___address, ab_name, _W_address, inbound),
	}
	return true
}
func add_iDB_AB_Address_List(public, private bool, ab_name _Name, inbound ...any) (ok bool) {
	var (
		interim_AB     = make(map[_Name]bool)
		interim_FQDN   = make(map[_FQDN]bool)
		interim_Prefix = make(map[netip.Prefix]bool)
	)
	for _, address := range inbound {
		switch value := (address).(type) {
		case netip.Addr:
			parse_iDB_AB_Prefix(public, private, ab_name, netip_Addr_Prefix(&value), interim_Prefix)
		case netip.Prefix:
			parse_iDB_AB_Prefix(public, private, ab_name, value, interim_Prefix)
		case _FQDN:
			parse_iDB_AB_FQDN(public, private, ab_name, value, interim_FQDN)
		case _Name:
			parse_iDB_AB_Name(public, private, ab_name, value, interim_AB)
		case []netip.Addr:
			for _, f := range value {
				parse_iDB_AB_Prefix(public, private, ab_name, netip_Addr_Prefix(&f), interim_Prefix)
			}
		case []netip.Prefix:
			for _, f := range value {
				parse_iDB_AB_Prefix(public, private, ab_name, f, interim_Prefix)
			}
		case []_FQDN:
			for _, f := range value {
				parse_iDB_AB_FQDN(public, private, ab_name, f, interim_FQDN)
			}
		case []_Name:
			for _, f := range value {
				parse_iDB_AB_Name(public, private, ab_name, f, interim_AB)
			}
		}
	}

	switch _, flag := i_ab[ab_name]; {
	case flag && i_ab[ab_name].Type == _Type_set:
		for a := range interim_AB {
			i_ab[ab_name].Set[a] = &i_AB_Set{
				Type:      _Type_set,
				GT_Action: join_string(" ", _W_address__set, a),
			}
			// create_iDB_AB_Set(a)
		}
		for a := range interim_FQDN {
			i_ab[ab_name].Set[_Name(a)] = &i_AB_Set{
				Type:      _Type_fqdn,
				GT_Action: join_string(" ", _W_address, a),
			}
			create_iDB_AB_FQDN("", a)
		}
		for a := range interim_Prefix {
			i_ab[ab_name].Set[_Name(a.String())] = &i_AB_Set{
				Type:      _Type_ipprefix,
				GT_Action: join_string(" ", _W_address, a),
			}
			create_iDB_AB_Prefix("", a)
		}
	case flag:
		log.Debugf("AB '%+v''%+v', already exist; ACTION: skip.", ab_name, i_ab[ab_name])
		return
	default:
		for a := range interim_FQDN {
			create_iDB_AB_FQDN(ab_name, a)
		}
		for a := range interim_Prefix {
			create_iDB_AB_Prefix(ab_name, a)
		}
	}
	return true
}
func parse_iDB_Route_Leak(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak __W_Route_Leak_FromTo) (outbound __W_Route_Leak_FromTo) {
	outbound = make(__W_Route_Leak_FromTo)
	var (
		v_RL_Import = func() (outbound []_Name) {
			for _, b := range route_leak[_W_import].PS {
				switch _, flag := i_ps[b]; {
				case !flag:
					log.Warnf("Peer '%v', PL '%v' not found; ACTION: ignore.", v_Peer.ASN, b)
					continue
				}
				outbound = append(outbound, b)
				v_Peer.link_PS(b)
			}
			return
		}()
		v_RL_Export = func() (outbound []_Name) {
			for _, b := range route_leak[_W_export].PS {
				switch _, flag := i_ps[b]; {
				case !flag:
					log.Warnf("Peer '%v', PL '%v' not found; ACTION: ignore.", v_Peer.ASN, b)
					continue
				}
				outbound = append(outbound, b)
				v_Peer.link_PS(b)
			}
			return
		}()
	)
	switch {
	case len(v_RL_Import) != 0:
		outbound[_W_import] = &i_Route_Leak_FromTo{
			PS:              v_RL_Import,
			GT_Action:       join_string(" ", _W_import, "[", v_RL_Import, "]"),
			_Attribute_List: route_leak[_W_import]._Attribute_List,
		}
	}
	switch {
	case len(v_RL_Export) != 0:
		outbound[_W_export] = &i_Route_Leak_FromTo{
			PS:              v_RL_Export,
			GT_Action:       join_string(" ", _W_export, "[", v_RL_Export, "]"),
			_Attribute_List: route_leak[_W_export]._Attribute_List,
		}
	}
	return
}

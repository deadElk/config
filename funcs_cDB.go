package main

import (
	"net/netip"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func parse_cDB_Peer_Router_ID(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch {
	case peer.Router_ID.IsValid():
		v_Peer.Router_ID = peer.Router_ID
	default:
		v_Peer.Router_ID = func() netip.Addr {
			for a := range v_Peer.RI[_S_RI].IF[_Name_lo0_0].IP {
				switch {
				case a.IsValid():
					return a.Addr()
				}
			}
			return parse_interface(netip.ParseAddr("192.0.2.0")).(netip.Addr)
		}()
		log.Debugf("Peer '%v', invalid Router_ID '%v'; ACTION: use '%v'.", peer.ASN, peer.Router_ID, v_Peer.Router_ID)
	}
	return true
}

func parse_cDB_Peer_IFM(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.IFM {
		v_Peer.IFM[b.Name] = i_Peer_IFM{
			Communication:   parse_Communication(&peer.ASN, &b.Name, &b.Communication),
			GT_Action:       strings_join(" ", _W_interfaces, b.Name),
			_Attribute_List: b._Attribute_List,
		}
	}
	return true
}
func parse_cDB_Peer_RI(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.RI {
		switch _, flag := v_Peer.RI[b.Name]; {
		case flag:
			log.Warnf("Peer '%v', RI '%v' already exist; ACTION: ignore.", peer.ASN, b.Name)
			continue
		}
		cDB_PO_PS_List{
			0: {Name: _Name(strings_join("_", _W_redistribute, b.Name)),
				Term: []cDB_PO_PS_Term{
					// 0: {Name: empty_Name.next_ID(),
					0: {Name: "PERMIT",
						From:            []cDB_PO_PS_From{0: {RI: b.Name, _Attribute_List: _Attribute_List{}}},
						Then:            []cDB_PO_PS_Then{0: {Action: _W_accept, _Attribute_List: _Attribute_List{}}},
						_Attribute_List: _Attribute_List{},
					},
				},
				_Attribute_List: _Attribute_List{},
			},
		}.parse()
		v_Peer.link_PS(_Name(strings_join("_", _W_redistribute, b.Name)))
	}
	for _, b := range peer.RI {
		switch _, flag := v_Peer.RI[b.Name]; {
		case flag:
			log.Warnf("Peer '%v', RI '%v' already exist; ACTION: ignore.", peer.ASN, b.Name)
			continue
		}
		var (
			v_IP_2_IF = make(map[netip.Addr]_Name)
			v_IF      = func() (outbound map[_Name]i_Peer_RI_IF) {
				outbound = make(map[_Name]i_Peer_RI_IF)
				for _, d := range b.IF {
					switch value, flag := v_Peer.IF_2_RI[d.Name]; {
					case flag:
						log.Warnf("Peer '%v', RI '%v', IF '%v' already exist in RI '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, value)
						continue
					}
					v_Peer.IF_2_RI[d.Name] = b.Name
					var (
						v_IF_IFM  string
						v_IF_IFsM string
					)
					split_2_string(&d.Name, re_dot, &v_IF_IFM, &v_IF_IFsM)
					outbound[d.Name] = i_Peer_RI_IF{
						IFM:           _Name(v_IF_IFM),
						IFsM:          _Name(v_IF_IFsM),
						Communication: parse_Communication(&peer.ASN, &d.Name, &d.Communication),
						IP: func() (outbound map[netip.Prefix]i_Peer_RI_IF_IP) {
							outbound = make(map[netip.Prefix]i_Peer_RI_IF_IP)
							for _, f := range d.IP {
								switch {
								case !f.DHCP:
									switch {
									case !f.IPPrefix.IsValid():
										log.Warnf("Peer '%v', RI '%v', IF '%v', invalid IP '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IPPrefix)
										continue
									}
									switch value, flag := v_IP_2_IF[f.IPPrefix.Addr()]; {
									case flag:
										log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' with IF '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IPPrefix, value)
										continue
									}
									v_IP_2_IF[f.IPPrefix.Addr()] = d.Name
								}
								add_iDB_AB_Address_List(true, false, _Name_PUBLIC, f.IPPrefix.Addr(), f.NAT)
								add_iDB_AB_Address_List(true, false, _Name(strings_join("", "O_AS", v_Peer.PName)), f.IPPrefix, f.NAT)
								add_iDB_AB_Address_List(false, true, _Name(strings_join("", "I_AS", v_Peer.PName)), f.IPPrefix, f.NAT)
								outbound[f.IPPrefix] = i_Peer_RI_IF_IP{
									Masked:          f.IPPrefix.Masked(),
									Primary:         f.Primary,
									Preferred:       f.Preferred,
									NAT:             f.NAT,
									DHCP:            f.DHCP,
									_Attribute_List: f._Attribute_List,
								}
							}
							return
						}(),
						PARP: func() (outbound map[netip.Addr]i_Peer_RI_IF_PARP) {
							outbound = make(map[netip.Addr]i_Peer_RI_IF_PARP)
							for _, f := range d.PARP {
								switch {
								case !f.IP.IsValid():
									log.Warnf("Peer '%v', RI '%v', IF '%v', invalid PARP IP '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IP)
									continue
								}
								switch value, flag := v_IP_2_IF[f.IP]; {
								case flag:
									log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' on IF '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IP, value)
									continue
								}
								v_IP_2_IF[f.IP] = d.Name
								add_iDB_AB_Address_List(true, false, _Name_PUBLIC, f.IP, f.NAT)
								outbound[f.IP] = i_Peer_RI_IF_PARP{
									NAT:             f.NAT,
									GT_Action:       strings_join(" ", _W_security___nat___proxy__arp),
									_Attribute_List: f._Attribute_List,
								}
							}
							return
						}(),
						GT_Action:       "",
						_Attribute_List: d._Attribute_List,
					}
				}
				return
			}()
			v_RT = func() (outbound map[netip.Prefix]i_Peer_RI_RO_RT) {
				outbound = make(map[netip.Prefix]i_Peer_RI_RO_RT)
				for _, d := range b.RT {
					switch {
					case !d.Identifier.IsValid():
						log.Warnf("Peer '%v', RI '%v', route Identifier '%v' is invalid; ACTION: ignore.", peer.ASN, b.Name, d.Identifier)
						continue
					}
					outbound[d.Identifier] = i_Peer_RI_RO_RT{
						GW: func() (outbound map[_Name]i_Peer_RI_RO_RT_GW) {
							outbound = make(map[_Name]i_Peer_RI_RO_RT_GW)
							for _, f := range d.GW {
								var (
									v_RT_IP          netip.Addr
									v_RT_IF          _Name
									v_RT_Table       _Name
									v_RT_Action      = f.Action.validate_RO_GW_Action(nil, v_Peer)
									v_RT_Action_Flag _W
									v_Action         = strings_join(" ", _W_static___route, d.Identifier)
								)
								switch {
								case v_RT_Action == _W_discard:
									v_Action = strings_join(" ", v_Action, v_RT_Action)
								case v_RT_Action == _W_next__table && len(f.Table) != 0:
									v_RT_Table = f.Table
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_Table)
								case (v_RT_Action == _W_next__hop || v_RT_Action == _W_qualified__next__hop) && len(f.IF) != 0:
									v_RT_IF = f.IF
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IF)
								case (v_RT_Action == _W_next__hop || v_RT_Action == _W_qualified__next__hop) && f.IP.IsValid():
									v_RT_IP = f.IP
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IP)
								case len(v_RT_Action) == 0 && len(f.Table) != 0:
									v_RT_Action = _W_next__table
									v_RT_Table = f.Table
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_Table)
								case len(v_RT_Action) == 0 && len(f.IF) != 0:
									v_RT_Action = _W_next__hop
									v_RT_IF = f.IF
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IF)
								case len(v_RT_Action) == 0 && f.IP.IsValid():
									v_RT_Action = _W_next__hop
									v_RT_IP = f.IP
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IP)
								case len(v_RT_Action) == 0:
									v_RT_Action = _W_discard
									v_Action = strings_join(" ", v_Action, v_RT_Action)
								default:
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', invalid GW '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Identifier, f)
									continue
								}
								switch {
								case f.Metric > 0:
									v_Action = strings_join(" ", v_Action, _W_metric, f.Metric)
									fallthrough
								case f.Preference > 0:
									v_Action = strings_join(" ", v_Action, _W_preference, f.Preference)
								}
								var (
									v_GW = i_Peer_RI_RO_RT_GW{
										IP:              v_RT_IP,
										IF:              v_RT_IF,
										Table:           v_RT_Table,
										Action:          v_RT_Action,
										Action_Flag:     v_RT_Action_Flag,
										Metric:          f.Metric,
										Preference:      f.Preference,
										GT_Action:       v_Action,
										_Attribute_List: f._Attribute_List,
									}
									v_Name = _Name(hash(&v_GW).String())
								)
								switch _, flag := outbound[v_Name]; {
								case flag:
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', GW '%v' already exist; ACTION: ignore.", peer.ASN, b.Name, d.Identifier, f)
									continue
								}
								outbound[v_Name] = v_GW
							}
							return
						}(),
						_Attribute_List: d._Attribute_List,
					}
				}
				return
			}()
			v_Action = func() string {
				switch {
				case b.Name != _S_RI:
					return strings_join(" ", _W_routing__instances, b.Name)
				}
				return ""
			}()
		)

		v_Peer.RI[b.Name] = i_Peer_RI{
			IP_2_IF:         v_IP_2_IF,
			IF:              v_IF,
			RT:              v_RT,
			Route_Leak:      parse_cDB_Route_Leak(peer, v_Peer, "", "", &b.Route_Leak),
			Protocol:        nil,
			BGP:             _BGP{BGP_Group: map[_Name]_BGP_Group{}, GT_Action: strings_join(" ", _W_protocols___bgp), _Attribute_List: _Attribute_List{}},
			GT_Action:       v_Action,
			_Attribute_List: b._Attribute_List,
		}
	}
	return true
}
func parse_cDB_Peer_Hostname(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch {
	case len(peer.Hostname) == 0:
		v_Peer.Hostname = _FQDN(strings_join("", "gw_as", pad(&peer.ASN, 10)))
		log.Warnf("Peer '%v', Hostname '%v' is invalid; ACTION: use '%v'.", peer.ASN, peer.Router_ID, v_Peer.Hostname)
	default:
		v_Peer.Hostname = peer.Hostname
	}
	return true
}
func parse_cDB_Peer_Domain_Name(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch {
	case len(peer.Domain_Name) == 0:
		v_Peer.Domain_Name = _S_domain_name
	default:
		v_Peer.Domain_Name = peer.Domain_Name
	}
	return true
}
func parse_cDB_Peer_Version(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	// var (
	// 	v_Major string
	// )
	// split_2_string(&peer.Version, re_caps, &v_Major)
	// v_Peer.Major = parse_interface(strconv.ParseFloat(v_Major, 64)).(float64)

	var (
		v_Version = re_caps.Split(peer.Version, -1)
	)
	v_Peer.Major = parse_interface(strconv.ParseFloat(v_Version[0], 64)).(float64)
	return true
}

func parse_cDB_Peer_GT_List(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch {
	case len(peer.GT_List) != 0:
		for _, b := range peer.GT_List {
			v_Peer.GT_List = append(v_Peer.GT_List, _Name(b))
		}
	default:
		v_Peer.GT_List = _S_GT_List
		v_Peer.GT_List = append(v_Peer.GT_List, v_Peer.ASName)
	}
	return true
}
func parse_cDB_Peer_SZ(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.SZ {
		switch {
		case b.Name == _S_mgmt_RI:
			log.Warnf("Peer '%v', SZ '%v' cannot be defined; ACTION: ignore.", peer.ASN, b.Name)
			continue
		}
		v_Peer.SZ[b.Name] = i_Peer_SZ{
			Screen: b.Screen,
			IF: func() (outbound map[_Name]i_Peer_SZ_IF) {
				outbound = make(map[_Name]i_Peer_SZ_IF)
				for c := range v_Peer.RI[b.Name].IF {
					outbound[c] = i_Peer_SZ_IF{
						_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
						GT_Action:                  strings_join(" ", _W_interfaces, c),
						_Attribute_List:            _Attribute_List{},
					}
				}
				return
			}(),
			_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
			GT_Action:                  strings_join(" ", _W_security__zones___security__zone, b.Name),
			_Attribute_List:            b._Attribute_List,
		}
	}
	for a := range v_Peer.RI {
		switch a {
		case _S_mgmt_RI:
			continue
		}
		switch _, flag := v_Peer.SZ[a]; {
		case !flag:
			v_Peer.SZ[a] = i_Peer_SZ{
				Screen:                     "",
				IF:                         map[_Name]i_Peer_SZ_IF{},
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
				GT_Action:                  strings_join(" ", _W_security__zones___security__zone, a),
				_Attribute_List:            _Attribute_List{},
			}
		}
		for e := range v_Peer.RI[a].IF {
			switch _, flag := v_Peer.SZ[a].IF[e]; {
			case flag:
				continue
			}
			v_Peer.SZ[a].IF[e] = i_Peer_SZ_IF{
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
				GT_Action:                  strings_join(" ", _W_interfaces, e),
				_Attribute_List:            _Attribute_List{},
			}
		}
	}

	return true
}
func parse_cDB_Peer_NAT(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	var (
		h = peer.NAT_Source
	)
	v_Peer.NAT[_Type_source] = i_Peer_NAT_Type{
		Address_Persistent: h.Address_Persistent,
		Pool:               parse_cDB_Pool(peer, v_Peer, _Type_source, _Type_pool, &h.Pool),
		Rule_Set:           parse_cDB_Rule_Set(peer, v_Peer, _Type_source, "", &h.Rule_Set),
		GT_Action:          strings_join(" ", _W_security___nat___source),
		_Attribute_List:    h._Attribute_List,
	}

	h = peer.NAT_Destination

	v_Peer.NAT[_Type_destination] = i_Peer_NAT_Type{
		Pool:            parse_cDB_Pool(peer, v_Peer, _Type_destination, _Type_pool, &h.Pool),
		Rule_Set:        parse_cDB_Rule_Set(peer, v_Peer, _Type_destination, "", &h.Rule_Set),
		GT_Action:       strings_join(" ", _W_security___nat___destination),
		_Attribute_List: h._Attribute_List,
	}

	h = peer.NAT_Static

	v_Peer.NAT[_Type_static] = i_Peer_NAT_Type{
		Pool:            parse_cDB_Pool(peer, v_Peer, _Type_static, _Type_pool, &h.Pool),
		Rule_Set:        parse_cDB_Rule_Set(peer, v_Peer, _Type_static, "", &h.Rule_Set),
		GT_Action:       strings_join(" ", _W_security___nat___static),
		_Attribute_List: h._Attribute_List,
	}
	return true
}
func parse_cDB_Peer_SP(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	v_Peer.SP.Option_List = _SP_Option_List{
		Default_Policy: func() _W {
			switch value := peer.SP_Option_List.Default_Policy; value {
			case _W_permit__all, _W_deny__all:
				return value
			case "":
				return _S_sp_default_policy
			default:
				log.Warnf("Peer '%v', unknown default security policy '%v'; ACTION: use '%v'.", peer.ASN, value, _S_sp_default_policy)
				return _S_sp_default_policy
			}
		}(),
		GT_Action: "",
	}
	for _, j := range peer.SP_Exact {
		for _, l := range j.To {
			for _, n := range j.From {
				v_Peer.SP.Exact = append(v_Peer.SP.Exact, i_Rule_Set{
					From:            parse_cDB_FromTo(peer, v_Peer, _Type_exact, _Type_from, &[]cDB_FromTo{0: n}),
					To:              parse_cDB_FromTo(peer, v_Peer, _Type_exact, _Type_to, &[]cDB_FromTo{0: l}),
					Rule:            parse_cDB_Rule(peer, v_Peer, _Type_exact, "", &j.Rule),
					GT_Action:       "",
					_Attribute_List: j._Attribute_List,
				})
				var (
					t = &v_Peer.SP.Exact[len(v_Peer.SP.Exact)-1]
				)
				switch {
				case len(t.From) != 1 || len(t.To) != 1:
					continue
				}
				t.GT_Action = strings_join(" ", _W_security___policies, _W_from__zone, t.From[0].SZ, _W_to__zone, t.To[0].SZ)
			}
		}
	}
	for _, j := range peer.SP_Global {
		v_Peer.SP.Global = append(v_Peer.SP.Global, i_Rule{
			Name:            j.Name,
			JA:              parse_cDB_Match_2_Name(peer, v_Peer, &j.Match),
			From:            parse_cDB_FromTo(peer, v_Peer, _Type_global, _Type_from, &j.From),
			To:              parse_cDB_FromTo(peer, v_Peer, _Type_global, _Type_to, &j.To),
			Then:            parse_cDB_Then(peer, v_Peer, _Type_global, _Type_then, &j.Then),
			GT_Action:       strings_join(" ", _W_security___policies___global___policy, j.Name),
			_Attribute_List: j._Attribute_List,
		})
	}
	return true
}
func parse_cDB_Peer_FW(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.FW {
		v_Peer.FW = append(v_Peer.FW, i_FW{
			Name: b.Name,
			Term: func() (outbound []i_FW_Term) {
				for _, d := range b.Term {
					outbound = append(outbound, i_FW_Term{
						Name: d.Name,
						From: func() (outbound []i_FW_FromTo) {
							for _, f := range d.From {
								outbound = append(outbound, i_FW_FromTo{
									PL:              f.PL,
									GT_Action:       f.PL.action_PL(peer, v_Peer, _Type_firewall, _Type_from),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						To: func() (outbound []i_FW_FromTo) {
							for _, f := range d.To {
								outbound = append(outbound, i_FW_FromTo{
									PL:              f.PL,
									GT_Action:       f.PL.action_PL(peer, v_Peer, _Type_firewall, _Type_to),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						Then: func() (outbound []i_FW_Then) {
							for _, f := range d.Then {
								outbound = append(outbound, i_FW_Then{
									Action:          f.Action,
									Action_Flag:     f.Action_Flag,
									RI:              f.RI,
									GT_Action:       strings_join(" ", _W_then, f.Action, f.Action_Flag, f.RI.action_RI(peer, v_Peer, _Type_firewall, _Type_then)),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						GT_Action:       strings_join(" ", _W_term, d.Name),
						_Attribute_List: d._Attribute_List,
					})
				}
				return
			}(),
			GT_Action:       strings_join(" ", _W_firewall___filter, b.Name),
			_Attribute_List: b._Attribute_List,
		})
	}
	return true
}

func parse_cDB_Pool(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Pool) (outbound map[_Name]i_Pool) {
	outbound = make(map[_Name]i_Pool)
	for _, j := range *inbound {
		switch {
		case !j.IPPrefix.IsValid():
			log.Warnf("Peer '%v', Pool '%v', invalid IP '%v'; ACTION: skip.", peer.ASN, j.Name, j.IPPrefix)
			continue
		}
		outbound[j.Name] = i_Pool{
			IPPrefix:  j.IPPrefix,
			RI:        j.RI,
			SZ:        j.SZ,
			Port:      j.Port,
			Port_Low:  j.Port_Low,
			Port_High: j.Port_High,
			GT_Action: strings_join(" ",
				j.RI.action_RI(peer, v_Peer, inbound_type, inbound_direction),
				j.SZ.action_SZ(peer, v_Peer, inbound_type, inbound_direction),
				action_Port(peer, v_Peer, inbound_type, inbound_direction, j.Port, j.Port_Low, j.Port_High),
			),
			_Attribute_List: j._Attribute_List,
		}
	}
	return
}
func parse_cDB_Rule_Set(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Rule_Set) (outbound map[_Name]i_Rule_Set) {
	outbound = make(map[_Name]i_Rule_Set)
	for _, j := range *inbound {
		outbound[j.Name] = i_Rule_Set{
			Name:            j.Name,
			From:            parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_from, &j.From),
			To:              parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_to, &j.To),
			Rule:            parse_cDB_Rule(peer, v_Peer, inbound_type, inbound_direction, &j.Rule),
			GT_Action:       strings_join(" ", _W_rule__set, j.Name),
			_Attribute_List: j._Attribute_List,
		}
	}
	return
}
func parse_cDB_Rule(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Rule) (outbound []i_Rule) {
	for _, j := range *inbound {
		outbound = append(outbound, i_Rule{
			Name:            j.Name,
			JA:              parse_cDB_Match_2_Name(peer, v_Peer, &j.Match),
			From:            parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_from, &j.From),
			To:              parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_to, &j.To),
			Then:            parse_cDB_Then(peer, v_Peer, inbound_type, _Type_then, &j.Then),
			GT_Action:       j.Name.String(),
			_Attribute_List: j._Attribute_List,
		})
	}
	return
}
func parse_cDB_Match_2_Name(peer *cDB_Peer, v_Peer *i_Peer, inbound *[]cDB_Match) (outbound []_Name) {
	for _, j := range *inbound {
		switch _, flag := i_ja[j.Application]; {
		// todo
		case parse_interface(regexp.MatchString("^(junos-|any$)", string(j.Application))).(bool):
		case len(j.Application) != 0 && !flag:
			log.Warnf("Peer '%v', unknown Application '%v'; ACTION: skip.", peer.ASN, j.Application)
			continue
		}
		outbound = append(outbound, j.Application)
		v_Peer.link_JA(j.Application)
	}
	return
}
func parse_cDB_Then(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Then) (outbound []i_Then) {
	for _, j := range *inbound {
		outbound = append(outbound, i_Then{
			Action:      j.Action,
			Action_Flag: j.Action_Flag,
			Pool:        j.Pool,
			AB:          j.AB,
			RI:          j.RI,
			Port_Low:    j.Port_Low,
			Port_High:   j.Port_High,
			GT_Action: strings_join(" ", j.Action, j.Action_Flag,
				j.AB.action_AB(peer, v_Peer, inbound_type, inbound_direction),
				j.RI.action_RI(peer, v_Peer, inbound_type, inbound_direction),
				j.Pool.action_Pool(peer, v_Peer, inbound_type, inbound_direction),
				action_Port(peer, v_Peer, inbound_type, inbound_direction, 0, j.Port_Low, j.Port_High),
			),
			_Attribute_List: j._Attribute_List,
		})
	}
	return
}
func parse_cDB_FromTo(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_FromTo) (outbound []i_FromTo) {
	for _, j := range *inbound {
		outbound = append(outbound, i_FromTo{
			AB:        j.AB,
			IF:        j.IF,
			RG:        j.RG,
			RI:        j.RI,
			SZ:        j.SZ,
			Port_Low:  j.Port_Low,
			Port_High: j.Port_High,
			GT_Action: strings_join(" ",
				j.AB.action_AB(peer, v_Peer, inbound_type, inbound_direction),
				j.IF.action_IF(peer, v_Peer, inbound_type, inbound_direction),
				j.RI.action_RI(peer, v_Peer, inbound_type, inbound_direction),
				j.SZ.action_SZ(peer, v_Peer, inbound_type, inbound_direction),
				action_Port(peer, v_Peer, inbound_type, inbound_direction, 0, j.Port_Low, j.Port_High),
			),
			_Attribute_List: j._Attribute_List,
		})
	}
	return
}
func parse_cDB_Route_Leak(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak *cDB_Peer_RI_RO_Route_Leak) (outbound map[_W]i_Route_Leak_FromTo) {
	// outbound = make(map[_W]i_Route_Leak_FromTo)
	return parse_iDB_Route_Leak(nil, v_Peer, "", "", map[_W]*i_Route_Leak_FromTo{
		_W_import: {PS: func() (outbound []_Name) {
			for _, b := range (*route_leak).Import {
				outbound = append(outbound, b.PS)
			}
			return
		}()},
		_W_export: {PS: func() (outbound []_Name) {
			for _, b := range (*route_leak).Export {
				outbound = append(outbound, b.PS)
			}
			return
		}()},
	})
}

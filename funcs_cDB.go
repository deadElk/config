package main

import (
	"net/netip"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func parse_cDB(xml_db *cDB) (ok bool) {
	set_loglevel(xml_db.Verbosity)
	switch len(xml_db.GT_Path) == 0 {
	case false:
		_Defaults[_path_GT] = xml_db.GT_Path
	}
	switch read_GT() {
	case false:
		log.Warnf("templates read error; ACTION: skip.")
		return
	}
	set_VI_IPPrefix(xml_db.VI_IPPrefix)
	set_Domain_Name(xml_db.Domain_Name)
	_Defaults[_GT_list] = []_Name{}
	for _, b := range re_period.Split(xml_db.GT_List, -1) {
		_Defaults[_GT_list] = append(_Defaults[_GT_list].([]_Name), _Name(b))
	}
	switch len(xml_db.Upload_Path) == 0 {
	case false:
		_Defaults[_path_out] = xml_db.Upload_Path
	}
	create_AB("OUTER_LIST", &_Service_Attributes{})

	parse_cDB_AB(&xml_db.AB)
	parse_cDB_JA(&xml_db.JA)
	parse_cDB_PL(&xml_db.PL)
	parse_cDB_PS(&xml_db.PS)
	parse_cDB_Peer(&xml_db.Peer)
	parse_cDB_VI(&xml_db.VI)

	return true
}

func parse_cDB_AB(inbound *[]cDB_AB) (ok bool) {
	for _, b := range *inbound {
		switch b.Set {
		case true:
			switch create_AB(b.Name, &b._Service_Attributes); {
			case false:
				continue
			}
		}
		for _, d := range b.Address {
			add_2_AB(true, true, b.Name, d.AB, d.FQDN, d.IPPrefix)
		}
	}
	return true
}
func parse_cDB_JA(inbound *[]cDB_JA) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_ja[b.Name]; flag {
		case true:
			log.Warnf("Application '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ja[b.Name] = func() (outbound *i_JA) {
			outbound = &i_JA{
				Term: func() (outbound []i_JA_Term) {
					for _, d := range b.Term {
						outbound = append(outbound, i_JA_Term{
							Name:                d.Name,
							Protocol:            d.Protocol,
							Destination_Port:    d.Destination_Port,
							_Service_Attributes: d._Service_Attributes,
						})
					}
					return
				}(),
				_Service_Attributes: b._Service_Attributes,
			}
			return
		}()
	}
	return true
}
func parse_cDB_PL(inbound *[]cDB_PO_PL) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_pl[b.Name]; flag {
		case true:
			log.Warnf("Policy List '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_pl[b.Name] = func() (outbound *i_PO_PL) {
			outbound = &i_PO_PL{
				Match: func() (outbound []i_PO_PL_Match) {
					for _, d := range b.Match {
						outbound = append(outbound, i_PO_PL_Match{
							IPPrefix:            d.IPPrefix,
							_Service_Attributes: d._Service_Attributes,
						})
					}
					return
				}(),
				_Service_Attributes: b._Service_Attributes,
			}
			return
		}()
	}
	return true
}
func parse_cDB_PS(inbound *[]cDB_PO_PS) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_ps[b.Name]; flag {
		case true:
			log.Warnf("Policy Statement '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ps[b.Name] = func() (outbound *i_PO_PS) {
			outbound = &i_PO_PS{
				Term: func() (outbound []i_PO_PS_Term) {
					for _, d := range b.Term {
						outbound = append(outbound, i_PO_PS_Term{
							Name: d.Name,
							From: func() (outbound []i_PO_PS_From) {
								for _, f := range d.From {
									outbound = append(outbound, i_PO_PS_From{
										Protocol:            f.Protocol,
										Route_Type:          f.Route_Type,
										PL:                  f.PL,
										Mask:                f.Mask,
										_Service_Attributes: f._Service_Attributes,
									})
								}
								return
							}(),
							Then: func() (outbound []i_PO_PS_Then) {
								for _, f := range d.Then {
									outbound = append(outbound, i_PO_PS_Then{
										Action:              f.Action,
										Action_Flag:         f.Action_Flag,
										Metric:              f.Metric,
										_Service_Attributes: f._Service_Attributes,
									})
								}
								return
							}(),
							_Service_Attributes: d._Service_Attributes,
						})
					}
					return
				}(),
				_Service_Attributes: b._Service_Attributes,
			}
			return
		}()
	}
	return true
}
func parse_cDB_Peer(inbound *[]cDB_Peer) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_peer[b.ASN]; flag {
		case true:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		}
		parse_cDB_AB(&b.AB)
		parse_cDB_JA(&b.JA)
		parse_cDB_PL(&b.PL)
		parse_cDB_PS(&b.PS)
	}
	for _, b := range *inbound {
		switch _, flag := i_peer[b.ASN]; flag {
		case true:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		}
		var (
			v_Peer = i_Peer{
				ASN:                 b.ASN,
				PName:               pad(&b.ASN, 10),
				Router_ID:           netip.Addr{},
				IF_2_RI:             map[_Name]_Name{},
				VI:                  map[_VI_ID]*i_VI{},
				VI_Left:             map[_VI_ID]*i_VI_Peer{},
				VI_Right:            map[_VI_ID]*i_VI_Peer{},
				IFM:                 map[_Name]i_Peer_IFM{},
				RI:                  map[_Name]i_Peer_RI{},
				Hostname:            "",
				Domain_Name:         "",
				Version:             b.Version,
				Major:               0,
				Manufacturer:        b.Manufacturer,
				Model:               b.Model,
				Serial:              b.Serial,
				Root:                b.Root.validate(16),
				GT_List:             []_Name{},
				SZ:                  map[_Name]i_SZ{},
				NAT:                 map[_Type]i_NAT{},
				SP_Exact:            []i_Rule_Set{},
				SP_Global:           []i_Rule{},
				AB:                  map[_Name]*i_AB{},
				JA:                  map[_Name]*i_JA{},
				PL:                  map[_Name]*i_PO_PL{},
				PS:                  map[_Name]*i_PO_PS{},
				i_SP_Options:        i_SP_Options{},
				_Service_Attributes: b._Service_Attributes,
			}
		)
		create_AB("O_AS"+_Name(v_Peer.PName), &_Service_Attributes{})
		create_AB("I_AS"+_Name(v_Peer.PName), &_Service_Attributes{})
		v_Peer.link_AB("OUTER_LIST", "O_AS"+_Name(v_Peer.PName), "I_AS"+_Name(v_Peer.PName))
		parse_cDB_Peer_Version(&b, &v_Peer)
		parse_cDB_Peer_RI(&b, &v_Peer)

		// PName
		parse_cDB_Peer_Router_ID(&b, &v_Peer)
		// IF_2_RI
		// VI
		// VI_Left
		// VI_Right
		parse_cDB_Peer_IFM(&b, &v_Peer)
		// RI
		parse_cDB_Peer_Hostname(&b, &v_Peer)
		parse_cDB_Peer_Domain_Name(&b, &v_Peer)
		// Version
		// Major
		// Manufacturer
		// Model
		// Serial
		// Root
		parse_cDB_Peer_GT_List(&b, &v_Peer)
		parse_cDB_Peer_SZ(&b, &v_Peer)
		parse_cDB_Peer_NAT(&b, &v_Peer)
		parse_cDB_Peer_SP_Exact(&b, &v_Peer)
		parse_cDB_Peer_SP_Global(&b, &v_Peer)

		parse_cDB_Peer_SP_Options(&b, &v_Peer)

		i_peer[b.ASN] = v_Peer
		ok = true

	}
	return
}
func parse_cDB_VI(inbound *[]cDB_VI) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_vi[b.ID]; flag {
		case true:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ID)
			continue
		}
		var (
			v_vi_peer_list = make(map[_VI_Peer_ID]_ASN)
		)
		i_vi[b.ID] = &i_VI{
			PName:               pad(&b.ID, 5),
			IPPrefix:            get_VI_IPPrefix(b.ID, 0).Masked(),
			IKE_No_NAT:          false,
			IKE_GCM:             false,
			Type:                b.Type,
			Communication:       b.Communication,
			Route_Metric:        b.Route_Metric,
			PSK:                 b.PSK.validate(64),
			_Service_Attributes: b._Service_Attributes,
		}
		i_vi_peer[b.ID] = map[_VI_Peer_ID]*i_VI_Peer{}

		for _, d := range b.Peer {
			switch /*d.ID >= 0 &&*/ d.ID <= 1 {
			case false:
				log.Warnf("VI '%v', Peer '%v', index out of range; ACTION: skip.", b.ID, d.ID)
				continue
			}
			switch _, flag := i_vi_peer[b.ID][d.ID]; flag {
			case true:
				log.Warnf("VI '%v', Peer '%v' already exist; ACTION: skip.", b.ID, d.ID)
				continue
			}
			var (
				v_RI                = d.RI.validate_RI(_Defaults[_mgmt_RI].(_Name))
				v_IF                = d.IF
				v_IP                = d.IP
				v_NAT               = netip.Addr{}
				v_IKE_Local_Address bool
			)

			v_vi_peer_list[d.ID] = d.ASN
			i_vi_peer[b.ID][d.ID] = &i_VI_Peer{
				ASN:                 d.ASN,
				RI:                  v_RI,
				IF:                  v_IF,
				IP:                  v_IP,
				NAT:                 v_NAT,
				IKE_Local_Address:   v_IKE_Local_Address,
				Dynamic:             d.Dynamic,
				Inner_RI:            d.Inner_RI.validate_RI(_Defaults[_mgmt_RI].(_Name)),
				Inner_IP:            get_VI_IPPrefix(b.ID, d.ID+1).Addr(),
				Inner_IPPrefix:      get_VI_IPPrefix(b.ID, d.ID+1),
				_Service_Attributes: d._Service_Attributes,
			}
		}

		switch len(v_vi_peer_list) != 2 {
		case true:
			continue
		}
		i_peer[v_vi_peer_list[0]].VI[b.ID] = i_vi[b.ID]
		i_peer[v_vi_peer_list[0]].VI_Left[b.ID] = i_vi_peer[b.ID][0]
		i_peer[v_vi_peer_list[0]].VI_Right[b.ID] = i_vi_peer[b.ID][1]
		i_peer[v_vi_peer_list[1]].VI[b.ID] = i_vi[b.ID]
		i_peer[v_vi_peer_list[1]].VI_Left[b.ID] = i_vi_peer[b.ID][1]
		i_peer[v_vi_peer_list[1]].VI_Right[b.ID] = i_vi_peer[b.ID][0]
	}
	return true
}

func parse_cDB_Peer_Router_ID(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch peer.Router_ID.IsValid() {
	case true:
		v_Peer.Router_ID = peer.Router_ID
	default:
		v_Peer.Router_ID = func() netip.Addr {
			for a := range v_Peer.RI["master"].IF["lo0.0"].IP {
				switch a.IsValid() {
				case true:
					return a.Addr()
				}
			}
			return parse_interface(netip.ParseAddr("192.0.2.0")).(netip.Addr)
		}()
		log.Warnf("Peer '%v', invalid Router_ID '%v'; ACTION: use '%v'.", peer.ASN, peer.Router_ID, v_Peer.Router_ID)
	}
	return true
}

func parse_cDB_Peer_IFM(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.IFM {
		v_Peer.IFM[b.Name] = i_Peer_IFM{
			Communication:       parse_Communication(&peer.ASN, &b.Name, &b.Communication),
			_Service_Attributes: b._Service_Attributes,
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
		switch _, flag := i_ps["redistribute_"+b.Name]; {
		case !flag:
			i_ps["redistribute_"+b.Name] = &i_PO_PS{
				Term: []i_PO_PS_Term{
					0: {
						Name:                "PERMIT",
						From:                []i_PO_PS_From{0: {RI: b.Name, _Service_Attributes: _Service_Attributes{}}},
						Then:                []i_PO_PS_Then{0: {Action: _Action_accept, _Service_Attributes: _Service_Attributes{}}},
						_Service_Attributes: _Service_Attributes{},
					},
				},
				_Service_Attributes: _Service_Attributes{},
			}
			v_Peer.link_PS("redistribute_" + b.Name)
		}
	}
	for _, b := range peer.RI {
		switch _, flag := v_Peer.RI[b.Name]; flag {
		case true:
			log.Warnf("Peer '%v', RI '%v' already exist; ACTION: ignore.", peer.ASN, b.Name)
			continue
		}
		var (
			v_IP_2_IF = make(map[netip.Addr]_Name)
			v_IF      = func() (outbound map[_Name]i_Peer_RI_IF) {
				outbound = make(map[_Name]i_Peer_RI_IF)
				for _, d := range b.IF {
					switch value, flag := v_Peer.IF_2_RI[d.Name]; flag {
					case true:
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
								switch f.DHCP {
								case false:
									switch f.IPPrefix.IsValid() {
									case false:
										log.Warnf("Peer '%v', RI '%v', IF '%v', invalid IP '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IPPrefix)
										continue
									}
									switch value, flag := v_IP_2_IF[f.IPPrefix.Addr()]; flag {
									case true:
										log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' with IF '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IPPrefix, value)
										continue
									}
									v_IP_2_IF[f.IPPrefix.Addr()] = d.Name
								}
								add_2_AB(true, false, "OUTER_LIST", f.IPPrefix.Addr(), f.NAT)
								add_2_AB(true, false, "O_AS"+_Name(v_Peer.PName), f.IPPrefix, f.NAT)
								add_2_AB(false, true, "I_AS"+_Name(v_Peer.PName), f.IPPrefix, f.NAT)
								outbound[f.IPPrefix] = i_Peer_RI_IF_IP{
									Masked:              f.IPPrefix.Masked(),
									Primary:             f.Primary,
									Preferred:           f.Preferred,
									NAT:                 f.NAT,
									DHCP:                f.DHCP,
									_Service_Attributes: f._Service_Attributes,
								}
							}
							return
						}(),
						PARP: func() (outbound map[netip.Addr]i_Peer_RI_IF_PARP) {
							outbound = make(map[netip.Addr]i_Peer_RI_IF_PARP)
							for _, f := range d.PARP {
								switch f.IP.IsValid() {
								case false:
									log.Warnf("Peer '%v', RI '%v', IF '%v', invalid PARP IP '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IP)
									continue
								}
								switch value, flag := v_IP_2_IF[f.IP]; flag {
								case true:
									log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' on IF '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IP, value)
									continue
								}
								v_IP_2_IF[f.IP] = d.Name
								add_2_AB(true, false, "OUTER_LIST", f.IP, f.NAT)
								outbound[f.IP] = i_Peer_RI_IF_PARP{
									NAT:                 f.NAT,
									_Service_Attributes: f._Service_Attributes,
								}
							}
							return
						}(),
						_Service_Attributes: d._Service_Attributes,
					}
				}
				return
			}()
			v_RT = func() (outbound map[netip.Prefix]i_Peer_RI_RO_RT) {
				outbound = make(map[netip.Prefix]i_Peer_RI_RO_RT)
				for _, d := range b.RT {
					switch d.Identifier.IsValid() {
					case false:
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
									v_RT_Action      = c_Action[f.Action]
									v_RT_Action_Flag _Action
								)
								switch v_RT_Action = c_Action[f.Action]; {
								case v_RT_Action == _Action_discard:
								case v_RT_Action == _Action_next_table && len(f.Table) != 0:
									v_RT_Table = f.Table
								case (v_RT_Action == _Action_next_hop || v_RT_Action == _Action_qualified_next_hop) && len(f.IF) != 0:
									v_RT_IF = f.IF
								case (v_RT_Action == _Action_next_hop || v_RT_Action == _Action_qualified_next_hop) && f.IP.IsValid():
									v_RT_IP = f.IP
								case len(v_RT_Action) == 0 && len(f.Table) != 0:
									v_RT_Action = _Action_next_table
									v_RT_Table = f.Table
								case len(v_RT_Action) == 0 && len(f.IF) != 0:
									v_RT_Action = _Action_next_hop
									v_RT_IF = f.IF
								case len(v_RT_Action) == 0 && f.IP.IsValid():
									v_RT_Action = _Action_next_hop
									v_RT_IP = f.IP
								case len(v_RT_Action) == 0:
									v_RT_Action = _Action_discard
								default:
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', invalid GW '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Identifier, f)
									continue
								}
								var (
									v_GW = i_Peer_RI_RO_RT_GW{
										IP:                  v_RT_IP,
										IF:                  v_RT_IF,
										Table:               v_RT_Table,
										Action:              v_RT_Action,
										Action_Flag:         v_RT_Action_Flag,
										Metric:              f.Metric,
										Preference:          f.Preference,
										_Service_Attributes: f._Service_Attributes,
									}
									v_Name = _Name(hash(&v_GW).String())
								)
								switch _, flag := outbound[v_Name]; flag {
								case true:
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', GW '%v' already exist; ACTION: ignore.", peer.ASN, b.Name, d.Identifier, f)
									continue
								}
								outbound[v_Name] = v_GW
							}
							return
						}(),
						_Service_Attributes: d._Service_Attributes,
					}
				}
				return
			}()
		)
		v_Peer.RI[b.Name] = i_Peer_RI{
			IP_2_IF: v_IP_2_IF,
			IF:      v_IF,
			RT:      v_RT,
			Leak: map[_Action]i_Peer_RI_RO_Leak_FromTo{
				_Action_import: {
					PS: func() (outbound []_Name) {
						for _, d := range b.From {
							switch _, flag := i_ps[d.PS]; flag {
							case false:
								log.Warnf("Peer '%v', RI '%v', configured Policy List '%v' not found; ACTION: ignore.", peer.ASN, b.Name, d.PS)
								continue
							}
							outbound = append(outbound, d.PS)
							v_Peer.link_PS(d.PS)
						}
						return
					}(),
				},
				_Action_export: {
					PS: func() (outbound []_Name) {
						for _, d := range b.To {
							switch _, flag := i_ps[d.PS]; flag {
							case false:
								log.Warnf("Peer '%v', RI '%v', configured Policy List '%v' not found; ACTION: ignore.", peer.ASN, b.Name, d.PS)
								continue
							}
							outbound = append(outbound, d.PS)
							v_Peer.link_PS(d.PS)
						}
						return
					}(),
				},
			},
			_Service_Attributes: b._Service_Attributes,
		}
	}
	return true
}
func parse_cDB_Peer_Hostname(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch len(peer.Hostname) == 0 {
	case true:
		v_Peer.Hostname = "gw_as" + _FQDN(pad(&peer.ASN, 10))
		log.Warnf("Peer '%v', Hostname '%v' is invalid; ACTION: use '%v'.", peer.ASN, peer.Router_ID, v_Peer.Hostname)
	default:
		v_Peer.Hostname = peer.Hostname
	}
	return true
}
func parse_cDB_Peer_Domain_Name(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch len(peer.Domain_Name) == 0 {
	case true:
		v_Peer.Domain_Name = _Defaults[_domain_name].(_FQDN)
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
	switch len(peer.GT_List) == 0 {
	case false:
		for _, b := range peer.GT_List {
			v_Peer.GT_List = append(v_Peer.GT_List, _Name(b))
		}
	default:
		v_Peer.GT_List = _Defaults[_GT_list].([]_Name)
	}
	return true
}
func parse_cDB_Peer_SZ(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.SZ {
		switch {
		case b.Name == _Defaults[_mgmt_RI].(_Name):
			log.Warnf("Peer '%v', SZ '%v' cannot be defined; ACTION: ignore.", peer.ASN, b.Name)
			continue
		}
		v_Peer.SZ[b.Name] = i_SZ{
			Screen: b.Screen,
			IF: func() (outbound map[_Name]i_SZ_IF) {
				outbound = make(map[_Name]i_SZ_IF)
				for c := range v_Peer.RI[b.Name].IF {
					outbound[c] = i_SZ_IF{
						_Host_Inbound_Traffic: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
						_Service_Attributes:   _Service_Attributes{},
					}
				}
				return
			}(),
			_Host_Inbound_Traffic: parse_Host_Inbound_Traffic(),
			_Service_Attributes:   b._Service_Attributes,
		}
	}
	for a := range v_Peer.RI {
		switch a {
		case _Defaults[_mgmt_RI].(_Name):
			continue
		}
		switch _, flag := v_Peer.SZ[a]; flag {
		case false:
			v_Peer.SZ[a] = i_SZ{
				Screen:                "",
				IF:                    map[_Name]i_SZ_IF{},
				_Host_Inbound_Traffic: parse_Host_Inbound_Traffic(),
				_Service_Attributes:   _Service_Attributes{},
			}
		}
		for e := range v_Peer.RI[a].IF {
			switch _, flag := v_Peer.SZ[a].IF[e]; flag {
			case true:
				continue
			}
			v_Peer.SZ[a].IF[e] = i_SZ_IF{
				_Host_Inbound_Traffic: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
				_Service_Attributes:   _Service_Attributes{},
			}
		}
	}

	return true
}
func parse_cDB_Peer_NAT(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	var (
		h = peer.NAT_Source
	)
	v_Peer.NAT[_Type_source] = i_NAT{
		Address_Persistent:  h.Address_Persistent,
		Pool:                parse_cDB_Pool(peer, v_Peer, &h.Pool),
		Rule_Set:            parse_cDB_Rule_Set(peer, v_Peer, &h.Rule_Set),
		_Service_Attributes: h._Service_Attributes,
	}

	h = peer.NAT_Destination

	v_Peer.NAT[_Type_destination] = i_NAT{
		Pool:                parse_cDB_Pool(peer, v_Peer, &h.Pool),
		Rule_Set:            parse_cDB_Rule_Set(peer, v_Peer, &h.Rule_Set),
		_Service_Attributes: h._Service_Attributes,
	}

	h = peer.NAT_Static

	v_Peer.NAT[_Type_static] = i_NAT{
		Pool:                parse_cDB_Pool(peer, v_Peer, &h.Pool),
		Rule_Set:            parse_cDB_Rule_Set(peer, v_Peer, &h.Rule_Set),
		_Service_Attributes: h._Service_Attributes,
	}
	return true
}
func parse_cDB_Peer_SP_Exact(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, j := range peer.SP_Exact {
		for _, l := range j.To {
			for _, n := range j.From {
				v_Peer.SP_Exact = append(v_Peer.SP_Exact, i_Rule_Set{
					From:                parse_cDB_FromTo(peer, v_Peer, &[]cDB_FromTo{0: n}),
					To:                  parse_cDB_FromTo(peer, v_Peer, &[]cDB_FromTo{0: l}),
					Rule:                parse_cDB_Rule(peer, v_Peer, &j.Rule),
					_Service_Attributes: j._Service_Attributes,
				})
			}
		}
	}
	return true
}
func parse_cDB_Peer_SP_Global(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, j := range peer.SP_Global {
		v_Peer.SP_Global = append(v_Peer.SP_Global, i_Rule{
			Name:                j.Name,
			JA:                  parse_cDB_Match_2_Name(peer, v_Peer, &j.Match),
			From:                parse_cDB_FromTo(peer, v_Peer, &j.From),
			To:                  parse_cDB_FromTo(peer, v_Peer, &j.To),
			Then:                parse_cDB_Then(peer, v_Peer, &j.Then),
			_Service_Attributes: j._Service_Attributes,
		})
	}
	return true
}

func parse_cDB_Peer_SP_Options(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	v_Peer.i_SP_Options = i_SP_Options{
		SP_Default_Policy: func() _Action {
			switch value := peer.SP_Options.Default_Policy; value {
			case _Action_permit_all, _Action_deny_all:
				return value
			case "":
				return _Defaults[_sp_default_policy].(_Action)
			default:
				log.Warnf("Peer '%v', unknown default security policy '%v'; ACTION: use '%v'.", peer.ASN, value, _Defaults[_sp_default_policy])
				return _Defaults[_sp_default_policy].(_Action)
			}
		}(),
	}
	return true
}

func parse_cDB_Pool(peer *cDB_Peer, v_Peer *i_Peer, inbound *[]cDB_Pool) (outbound map[_Name]i_Pool) {
	outbound = make(map[_Name]i_Pool)
	for _, j := range *inbound {
		// todo: make it more elegant ....
		switch len(parse_interface(j.IPPrefix.MarshalText()).([]byte)) != 0 && !j.IPPrefix.IsValid() {
		case true:
			log.Warnf("Peer '%v', Pool '%v', invalid IP '%v'; ACTION: skip.", peer.ASN, j.Name, j.IPPrefix)
			continue
		}
		switch _, flag := v_Peer.RI[j.RI]; len(j.RI) != 0 && !flag {
		case true:
			log.Warnf("Peer '%v', Pool '%v', unknown RI '%v'; ACTION: skip.", peer.ASN, j.Name, j.RI)
			continue
		}
		switch _, flag := v_Peer.SZ[j.SZ]; len(j.SZ) != 0 && !flag {
		case true:
			log.Warnf("Peer '%v', Pool '%v', unknown SZ '%v'; ACTION: skip.", peer.ASN, j.Name, j.SZ)
			continue
		}
		outbound[j.Name] = i_Pool{
			IPPrefix:            j.IPPrefix,
			RI:                  j.RI,
			SZ:                  j.SZ,
			_Service_Attributes: j._Service_Attributes,
		}
	}
	return
}
func parse_cDB_Rule_Set(peer *cDB_Peer, v_Peer *i_Peer, inbound *[]cDB_Rule_Set) (outbound map[_Name]i_Rule_Set) {
	outbound = make(map[_Name]i_Rule_Set)
	for _, j := range *inbound {
		outbound[j.Name] = i_Rule_Set{
			From:                parse_cDB_FromTo(peer, v_Peer, &j.From),
			To:                  parse_cDB_FromTo(peer, v_Peer, &j.To),
			Rule:                parse_cDB_Rule(peer, v_Peer, &j.Rule),
			_Service_Attributes: j._Service_Attributes,
		}
	}
	return
}
func parse_cDB_Rule(peer *cDB_Peer, v_Peer *i_Peer, inbound *[]cDB_Rule) (outbound map[_Name]i_Rule) {
	outbound = make(map[_Name]i_Rule)
	for _, j := range *inbound {
		outbound[j.Name] = i_Rule{
			JA:                  parse_cDB_Match_2_Name(peer, v_Peer, &j.Match),
			From:                parse_cDB_FromTo(peer, v_Peer, &j.From),
			To:                  parse_cDB_FromTo(peer, v_Peer, &j.To),
			Then:                parse_cDB_Then(peer, v_Peer, &j.Then),
			_Service_Attributes: j._Service_Attributes,
		}
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
func parse_cDB_Then(peer *cDB_Peer, v_Peer *i_Peer, inbound *[]cDB_Then) (outbound []i_Then) {
	for _, j := range *inbound {
		switch _, flag := i_ab[j.AB]; {
		case len(j.AB) != 0 && !flag && j.AB != "any":
			log.Warnf("Peer '%v', unknown AB '%v'; ACTION: skip.", peer.ASN, j.AB)
			continue
		case len(j.AB) != 0 && flag && j.AB != "any":
			v_Peer.link_AB(j.AB)
		}
		switch _, flag := v_Peer.RI[j.RI]; len(j.RI) != 0 && !flag {
		case true:
			log.Warnf("Peer '%v', unknown RI '%v'; ACTION: skip.", peer.ASN, j.RI)
			continue
		}
		outbound = append(outbound, i_Then{
			Action:              j.Action,
			Action_Flag:         j.Action_Flag,
			Pool:                j.Pool,
			AB:                  j.AB,
			RI:                  j.RI,
			Port_Low:            j.Port_Low,
			Port_High:           j.Port_High,
			_Service_Attributes: j._Service_Attributes,
		})
	}
	return
}
func parse_cDB_FromTo(peer *cDB_Peer, v_Peer *i_Peer, inbound *[]cDB_FromTo) (outbound []i_FromTo) {
	for _, j := range *inbound {
		switch _, flag := i_ab[j.AB]; {
		case len(j.AB) != 0 && !flag && j.AB != "any":
			log.Warnf("Peer '%v', unknown AB '%v'; ACTION: skip.", peer.ASN, j.AB)
			continue
		case len(j.AB) != 0 && flag && j.AB != "any":
			v_Peer.link_AB(j.AB)
		}
		switch _, flag := v_Peer.IF_2_RI[j.IF]; {
		case len(j.IF) != 0 && !flag:
			log.Warnf("Peer '%v', unknown IF '%v'; ACTION: skip.", peer.ASN, j.IF)
			continue
		}
		// switch _, flag := v_Peer.RI[j.RI]; len(j.RG) != 0 && !flag {
		// case true:
		// log.Warnf("Peer '%v', invalid RG '%v'; ACTION: skip.", peer.ASN, j.RG)
		// continue
		// }
		switch _, flag := v_Peer.RI[j.RI]; {
		case len(j.RI) != 0 && !flag:
			log.Warnf("Peer '%v', unknown RI '%v'; ACTION: skip.", peer.ASN, j.RI)
			continue
		}
		switch _, flag := v_Peer.SZ[j.SZ]; {
		case len(j.SZ) != 0 && !flag && j.SZ != _Defaults[_host_RI].(_Name) && j.SZ != "any":
			log.Warnf("Peer '%v', unknown SZ '%v'; ACTION: skip.", peer.ASN, j.SZ)
			continue
		}
		outbound = append(outbound, i_FromTo{
			AB:                  j.AB,
			IF:                  j.IF,
			RG:                  j.RG,
			RI:                  j.RI,
			SZ:                  j.SZ,
			Port_Low:            j.Port_Low,
			Port_High:           j.Port_High,
			_Service_Attributes: j._Service_Attributes,
		})
	}
	return
}

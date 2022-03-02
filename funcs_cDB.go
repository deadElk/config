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
	parse_cDB_AB_create_Set("OUTER_LIST", &Attribute_List{})

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
			switch parse_cDB_AB_create_Set(b.Name, &b.Attribute_List); {
			case false:
				continue
			}
		}
		for _, d := range b.Address {
			parse_cDB_AB_add_Address(true, true, b.Name, d.AB, d.FQDN, d.IPPrefix)
		}
	}
	return true
}
func parse_cDB_JA(inbound *[]cDB_JA) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_ja[b.Name]; flag {
		case true:
			log.Debugf("Application '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ja[b.Name] = func() (outbound *i_JA) {
			outbound = &i_JA{
				Term: func() (outbound []i_JA_Term) {
					for _, d := range b.Term {
						outbound = append(outbound, i_JA_Term{
							Name:             d.Name,
							Protocol:         d.Protocol,
							Destination_Port: d.Destination_Port,
							GT_Action_List:   GT_Action_List{GT_Action: " term " + d.Name.String() + " protocol " + d.Protocol.String() + " destination-port " + d.Destination_Port.String()},
							Attribute_List:   d.Attribute_List,
						})
					}
					return
				}(),
				GT_Action_List: GT_Action_List{GT_Action: "set applications application " + b.Name.String()},
				Attribute_List: b.Attribute_List,
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
			log.Debugf("Policy List '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_pl[b.Name] = func() (outbound *i_PO_PL) {
			outbound = &i_PO_PL{
				Match: func() (outbound []i_PO_PL_Match) {
					for _, d := range b.Match {
						outbound = append(outbound, i_PO_PL_Match{
							IPPrefix:       d.IPPrefix,
							GT_Action_List: GT_Action_List{GT_Action: " default " + d.IPPrefix.String()},
							Attribute_List: d.Attribute_List,
						})
					}
					return
				}(),
				GT_Action_List: GT_Action_List{GT_Action: "set policy-options prefix-list " + b.Name.String()},
				Attribute_List: b.Attribute_List,
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
			log.Debugf("Policy Statement '%v' already exist; ACTION: skip.", b.Name)
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
									var (
										v_Action string
									)
									switch {
									case len(f.RI) != 0:
										v_Action = " routing-instance " + f.RI.String()
									case len(f.Protocol) != 0:
										v_Action = " protocol " + f.Protocol.String()
									case len(f.Route_Type) != 0:
										v_Action = " route-type " + f.Route_Type.String()
									case len(f.PL) != 0:
										v_Action = " prefix-list-filter " + f.PL.String() + " " + f.Mask.String()
									}
									outbound = append(outbound, i_PO_PS_From{
										RI:             f.RI,
										Protocol:       f.Protocol,
										Route_Type:     f.Route_Type,
										PL:             f.PL,
										Mask:           f.Mask,
										GT_Action_List: GT_Action_List{GT_Action: " from " + v_Action},
										Attribute_List: f.Attribute_List,
									})
								}
								return
							}(),
							Then: func() (outbound []i_PO_PS_Then) {
								for _, f := range d.Then {
									var (
										v_Action string
									)
									switch {
									case f.Metric != 0:
										v_Action = " metric " + f.Metric.String()
									}
									outbound = append(outbound, i_PO_PS_Then{
										Action:         f.Action,
										Action_Flag:    f.Action_Flag,
										Metric:         f.Metric,
										GT_Action_List: GT_Action_List{GT_Action: " then " + f.Action.String() + " " + f.Action_Flag.String() + v_Action},
										Attribute_List: f.Attribute_List,
									})
								}
								return
							}(),
							GT_Action_List: GT_Action_List{GT_Action: " term " + d.Name.String()},
							Attribute_List: d.Attribute_List,
						})
					}
					return
				}(),
				GT_Action_List: GT_Action_List{GT_Action: "set policy-options policy-statement " + b.Name.String()},
				Attribute_List: b.Attribute_List,
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
				ASN:             b.ASN,
				PName:           pad(&b.ASN, 10),
				Router_ID:       netip.Addr{},
				IF_2_RI:         map[_Name]_Name{},
				VI:              map[_VI_ID]*i_VI{},
				VI_Left:         map[_VI_ID]*i_VI_Peer{},
				VI_Right:        map[_VI_ID]*i_VI_Peer{},
				IFM:             map[_Name]i_Peer_IFM{},
				RI:              map[_Name]i_Peer_RI{},
				Hostname:        "",
				Domain_Name:     "",
				Version:         b.Version,
				Major:           0,
				Manufacturer:    b.Manufacturer,
				Model:           b.Model,
				Serial:          b.Serial,
				Root:            b.Root.validate(16),
				GT_List:         []_Name{},
				SZ:              map[_Name]i_Peer_SZ{},
				NAT:             map[_Type]i_Peer_NAT_Type{},
				SP_Exact:        []i_Rule_Set{},
				SP_Global:       []i_Rule{},
				AB:              map[_Name]*i_AB{},
				JA:              map[_Name]*i_JA{},
				PL:              map[_Name]*i_PO_PL{},
				PS:              map[_Name]*i_PO_PS{},
				IKE_Option_List: IKE_Option_List{},
				SP_Option_List:  SP_Option_List{},
				GT_Action_List:  GT_Action_List{},
				Attribute_List:  b.Attribute_List,
			}
		)
		parse_cDB_AB_create_Set("O_AS"+_Name(v_Peer.PName), &Attribute_List{})
		parse_cDB_AB_create_Set("I_AS"+_Name(v_Peer.PName), &Attribute_List{})
		v_Peer.link_AB("OUTER_LIST", "O_AS"+_Name(v_Peer.PName), "I_AS"+_Name(v_Peer.PName))
		parse_cDB_Peer_Version(&b, &v_Peer)
		v_Peer.IKE_Option_List.IKE_GCM = v_Peer.Major >= 12.3
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
			v_vi_peer_list = make(map[_VI_Peer_ID]*i_VI_Peer)
			v_IKE_GCM      bool
			v_IKE_No_NAT   bool
		)
		i_vi[b.ID] = &i_VI{
			PName:         pad(&b.ID, 5),
			IPPrefix:      get_VI_IPPrefix(b.ID, 0).Masked(),
			Type:          b.Type,
			Communication: b.Communication,
			Route_Metric:  b.Route_Metric,
			PSK:           b.PSK.validate(64),
			IKE_Option_List: IKE_Option_List{
				IKE_No_NAT: false,
			},
			GT_Action_List: GT_Action_List{},
			Attribute_List: b.Attribute_List,
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

			i_vi_peer[b.ID][d.ID] = &i_VI_Peer{
				ASN:            d.ASN,
				RI:             v_RI,
				IF:             v_IF,
				IP:             v_IP,
				NAT:            v_NAT,
				Dynamic:        d.Dynamic,
				Inner_RI:       d.Inner_RI.validate_RI(_Defaults[_mgmt_RI].(_Name)),
				Inner_IP:       get_VI_IPPrefix(b.ID, d.ID+1).Addr(),
				Inner_IPPrefix: get_VI_IPPrefix(b.ID, d.ID+1),
				IKE_Option_List: IKE_Option_List{
					IKE_GCM:           v_IKE_GCM,
					IKE_No_NAT:        v_IKE_No_NAT,
					IKE_Local_Address: v_IKE_Local_Address,
				},
				GT_Action_List: GT_Action_List{},
				Attribute_List: d.Attribute_List,
			}
			v_vi_peer_list[d.ID] = i_vi_peer[b.ID][d.ID]
		}

		var (
			_first, _second, _total _VI_Peer_ID
			_if                     = _Name("st0." + b.ID.String())
		)
		switch _total = _VI_Peer_ID(len(v_vi_peer_list)); _total != 2 {
		case true:
			continue
		}

		for _first, _second = 0, _total-1; _first <= _total-1; _first, _second = _first+1, _second-1 {
			i_peer[v_vi_peer_list[_first].ASN].VI[b.ID] = i_vi[b.ID]
			i_peer[v_vi_peer_list[_first].ASN].VI_Left[b.ID] = i_vi_peer[b.ID][_first]
			i_peer[v_vi_peer_list[_first].ASN].VI_Right[b.ID] = i_vi_peer[b.ID][_second]

			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = i_Peer_RI_IF{
				IFM:           "st0",
				IFsM:          _Name(b.ID.String()),
				Communication: _Defaults[_comm_vi].(_Communication),
				IP: map[netip.Prefix]i_Peer_RI_IF_IP{
					i_vi_peer[b.ID][_first].Inner_IPPrefix: {
						Masked:         i_vi_peer[b.ID][_first].Inner_IPPrefix.Masked(),
						Primary:        false,
						Preferred:      false,
						NAT:            netip.Addr{},
						DHCP:           false,
						GT_Action_List: GT_Action_List{},
						Attribute_List: Attribute_List{},
					},
				},
				PARP:           nil,
				GT_Action_List: GT_Action_List{},
				Attribute_List: Attribute_List{Description: _Description("" + i_vi_peer[b.ID][_first].IF.String() + "_AS" + pad(i_vi_peer[b.ID][_second].ASN.String(), 10).String() + "_" + i_vi_peer[b.ID][_second].IF.String())},
			}
			i_peer[v_vi_peer_list[_first].ASN].SZ[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = i_Peer_SZ_IF{
				Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh, _Protocol_bgp),
				GT_Action_List:            GT_Action_List{GT_Action: " interfaces " + _if.String()},
				Attribute_List:            Attribute_List{},
			}
			i_peer[v_vi_peer_list[_first].ASN].IF_2_RI[_if] = i_vi_peer[b.ID][_first].Inner_RI
			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].IP_2_IF[i_vi_peer[b.ID][_first].Inner_IP] = _if
		}
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
			Communication:  parse_Communication(&peer.ASN, &b.Name, &b.Communication),
			GT_Action_List: GT_Action_List{GT_Action: "set interfaces " + b.Name.String()},
			Attribute_List: b.Attribute_List,
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
		parse_cDB_PS(&[]cDB_PO_PS{
			0: {Name: "redistribute_" + b.Name,
				Term: []cDB_PO_PS_Term{
					0: {Name: "PERMIT",
						From:           []cDB_PO_PS_From{0: {RI: b.Name, Attribute_List: Attribute_List{}}},
						Then:           []cDB_PO_PS_Then{0: {Action: _Action_accept, Attribute_List: Attribute_List{}}},
						Attribute_List: Attribute_List{},
					},
				},
				Attribute_List: Attribute_List{},
			},
		})
		v_Peer.link_PS("redistribute_" + b.Name)
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
								parse_cDB_AB_add_Address(true, false, "OUTER_LIST", f.IPPrefix.Addr(), f.NAT)
								parse_cDB_AB_add_Address(true, false, "O_AS"+_Name(v_Peer.PName), f.IPPrefix, f.NAT)
								parse_cDB_AB_add_Address(false, true, "I_AS"+_Name(v_Peer.PName), f.IPPrefix, f.NAT)
								outbound[f.IPPrefix] = i_Peer_RI_IF_IP{
									Masked:         f.IPPrefix.Masked(),
									Primary:        f.Primary,
									Preferred:      f.Preferred,
									NAT:            f.NAT,
									DHCP:           f.DHCP,
									Attribute_List: f.Attribute_List,
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
								parse_cDB_AB_add_Address(true, false, "OUTER_LIST", f.IP, f.NAT)
								outbound[f.IP] = i_Peer_RI_IF_PARP{
									NAT:            f.NAT,
									Attribute_List: f.Attribute_List,
								}
							}
							return
						}(),
						Attribute_List: d.Attribute_List,
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
										IP:             v_RT_IP,
										IF:             v_RT_IF,
										Table:          v_RT_Table,
										Action:         v_RT_Action,
										Action_Flag:    v_RT_Action_Flag,
										Metric:         f.Metric,
										Preference:     f.Preference,
										Attribute_List: f.Attribute_List,
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
						Attribute_List: d.Attribute_List,
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
			Attribute_List: b.Attribute_List,
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
		// var
		// 	v_Action string
		// )
		// switch {
		// case len(b.Screen) != 0:
		// 	v_Action = " screen " + b.Screen.String()
		// }
		v_Peer.SZ[b.Name] = i_Peer_SZ{
			Screen: b.Screen,
			IF: func() (outbound map[_Name]i_Peer_SZ_IF) {
				outbound = make(map[_Name]i_Peer_SZ_IF)
				for c := range v_Peer.RI[b.Name].IF {
					outbound[c] = i_Peer_SZ_IF{
						Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
						GT_Action_List:            GT_Action_List{GT_Action: " interfaces " + c.String()},
						Attribute_List:            Attribute_List{},
					}
				}
				return
			}(),
			Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
			// GT_Action_List:            GT_Action_List{GT_Action: "set security zones security-zone " + b.Name.String() + v_Action},
			GT_Action_List: GT_Action_List{GT_Action: "set security zones security-zone " + b.Name.String()},
			Attribute_List: b.Attribute_List,
		}
	}
	for a := range v_Peer.RI {
		switch a {
		case _Defaults[_mgmt_RI].(_Name):
			continue
		}
		switch _, flag := v_Peer.SZ[a]; flag {
		case false:
			v_Peer.SZ[a] = i_Peer_SZ{
				Screen:                    "",
				IF:                        map[_Name]i_Peer_SZ_IF{},
				Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
				GT_Action_List:            GT_Action_List{GT_Action: "set security zones security-zone " + a.String()},
				Attribute_List:            Attribute_List{},
			}
		}
		for e := range v_Peer.RI[a].IF {
			switch _, flag := v_Peer.SZ[a].IF[e]; flag {
			case true:
				continue
			}
			v_Peer.SZ[a].IF[e] = i_Peer_SZ_IF{
				Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
				GT_Action_List:            GT_Action_List{GT_Action: " interfaces " + e.String()},
				Attribute_List:            Attribute_List{},
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
		GT_Action_List:     GT_Action_List{GT_Action: "set security nat source "},
		Attribute_List:     h.Attribute_List,
	}

	h = peer.NAT_Destination

	v_Peer.NAT[_Type_destination] = i_Peer_NAT_Type{
		Pool:           parse_cDB_Pool(peer, v_Peer, _Type_destination, _Type_pool, &h.Pool),
		Rule_Set:       parse_cDB_Rule_Set(peer, v_Peer, _Type_destination, "", &h.Rule_Set),
		GT_Action_List: GT_Action_List{GT_Action: "set security nat destination "},
		Attribute_List: h.Attribute_List,
	}

	h = peer.NAT_Static

	v_Peer.NAT[_Type_static] = i_Peer_NAT_Type{
		Pool:           parse_cDB_Pool(peer, v_Peer, _Type_static, _Type_pool, &h.Pool),
		Rule_Set:       parse_cDB_Rule_Set(peer, v_Peer, _Type_static, "", &h.Rule_Set),
		GT_Action_List: GT_Action_List{GT_Action: "set security nat static "},
		Attribute_List: h.Attribute_List,
	}
	return true
}
func parse_cDB_Peer_SP_Exact(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, j := range peer.SP_Exact {
		for _, l := range j.To {
			for _, n := range j.From {
				v_Peer.SP_Exact = append(v_Peer.SP_Exact, i_Rule_Set{
					From:           parse_cDB_FromTo(peer, v_Peer, _Type_exact, _Type_from, &[]cDB_FromTo{0: n}),
					To:             parse_cDB_FromTo(peer, v_Peer, _Type_exact, _Type_to, &[]cDB_FromTo{0: l}),
					Rule:           parse_cDB_Rule(peer, v_Peer, _Type_exact, "", &j.Rule),
					GT_Action_List: GT_Action_List{GT_Action: ""},
					Attribute_List: j.Attribute_List,
				})
				var (
					t = &v_Peer.SP_Exact[len(v_Peer.SP_Exact)-1]
				)
				switch len(t.From) != 1 || len(t.To) != 1 {
				case true:
					continue
				}
				t.GT_Action_List.GT_Action = "set security policies from-zone " + t.From[0].SZ.String() + " to-zone " + t.To[0].SZ.String()
			}
		}
	}
	return true
}
func parse_cDB_Peer_SP_Global(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, j := range peer.SP_Global {
		v_Peer.SP_Global = append(v_Peer.SP_Global, i_Rule{
			Name:           j.Name,
			JA:             parse_cDB_Match_2_Name(peer, v_Peer, &j.Match),
			From:           parse_cDB_FromTo(peer, v_Peer, _Type_global, _Type_from, &j.From),
			To:             parse_cDB_FromTo(peer, v_Peer, _Type_global, _Type_to, &j.To),
			Then:           parse_cDB_Then(peer, v_Peer, _Type_global, _Type_then, &j.Then),
			GT_Action_List: GT_Action_List{GT_Action: "set security policies global policy " + j.Name.String()},
			Attribute_List: j.Attribute_List,
		})
	}
	return true
}

func parse_cDB_Peer_SP_Options(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	v_Peer.SP_Option_List = SP_Option_List{
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

func parse_cDB_Pool(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Pool) (outbound map[_Name]i_Pool) {
	outbound = make(map[_Name]i_Pool)
	for _, j := range *inbound {
		var (
			v_Action string
		)
		// todo: make it more elegant ....
		switch {
		case !j.IPPrefix.IsValid():
			log.Warnf("Peer '%v', Pool '%v', invalid IP '%v'; ACTION: skip.", peer.ASN, j.Name, j.IPPrefix)
			continue
		}
		// v_Action = " address " + j.IPPrefix.String()
		v_Action += j.RI.action_RI(peer, v_Peer, inbound_type, inbound_direction)
		v_Action += j.SZ.action_SZ(peer, v_Peer, inbound_type, inbound_direction)
		outbound[j.Name] = i_Pool{
			IPPrefix: j.IPPrefix,
			RI:       j.RI,
			SZ:       j.SZ,
			// GT_Action_List: GT_Action_List{GT_Action: "pool " + j.Name.String() + v_Action},
			GT_Action_List: GT_Action_List{GT_Action: v_Action},
			Attribute_List: j.Attribute_List,
		}
	}
	return
}
func parse_cDB_Rule_Set(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Rule_Set) (outbound map[_Name]i_Rule_Set) {
	outbound = make(map[_Name]i_Rule_Set)
	for _, j := range *inbound {
		outbound[j.Name] = i_Rule_Set{
			Name:           j.Name,
			From:           parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_from, &j.From),
			To:             parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_to, &j.To),
			Rule:           parse_cDB_Rule(peer, v_Peer, inbound_type, inbound_direction, &j.Rule),
			GT_Action_List: GT_Action_List{GT_Action: "rule-set " + j.Name.String()},
			Attribute_List: j.Attribute_List,
		}
	}
	return
}
func parse_cDB_Rule(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_Rule) (outbound []i_Rule) {
	var (
		v_Action string
	)
	for _, j := range *inbound {
		outbound = append(outbound, i_Rule{
			Name:           j.Name,
			JA:             parse_cDB_Match_2_Name(peer, v_Peer, &j.Match),
			From:           parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_from, &j.From),
			To:             parse_cDB_FromTo(peer, v_Peer, inbound_type, _Type_to, &j.To),
			Then:           parse_cDB_Then(peer, v_Peer, inbound_type, _Type_then, &j.Then),
			GT_Action_List: GT_Action_List{GT_Action: "" + j.Name.String() + v_Action},
			Attribute_List: j.Attribute_List,
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
		var (
			v_Action string
		)
		v_Action += j.AB.action_AB(peer, v_Peer, inbound_type, inbound_direction)
		v_Action += j.RI.action_RI(peer, v_Peer, inbound_type, inbound_direction)
		switch {
		case len(j.Pool) != 0:
			v_Action += " pool " + j.Pool.String()
		}
		v_Action += action_Port(peer, v_Peer, inbound_type, inbound_direction, j.Port_Low, j.Port_High)
		outbound = append(outbound, i_Then{
			Action:         j.Action,
			Action_Flag:    j.Action_Flag,
			Pool:           j.Pool,
			AB:             j.AB,
			RI:             j.RI,
			Port_Low:       j.Port_Low,
			Port_High:      j.Port_High,
			GT_Action_List: GT_Action_List{GT_Action: "" + j.Action.String() + " " + j.Action_Flag.String() + " " + v_Action},
			Attribute_List: j.Attribute_List,
		})
	}
	return
}
func parse_cDB_FromTo(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound *[]cDB_FromTo) (outbound []i_FromTo) {
	for _, j := range *inbound {
		var (
			v_Action string
		)
		v_Action += j.AB.action_AB(peer, v_Peer, inbound_type, inbound_direction)
		v_Action += j.IF.action_IF(peer, v_Peer, inbound_type, inbound_direction)
		v_Action += j.RI.action_RI(peer, v_Peer, inbound_type, inbound_direction)
		v_Action += j.SZ.action_SZ(peer, v_Peer, inbound_type, inbound_direction)
		v_Action += action_Port(peer, v_Peer, inbound_type, inbound_direction, j.Port_Low, j.Port_High)
		outbound = append(outbound, i_FromTo{
			AB:             j.AB,
			IF:             j.IF,
			RG:             j.RG,
			RI:             j.RI,
			SZ:             j.SZ,
			Port_Low:       j.Port_Low,
			Port_High:      j.Port_High,
			GT_Action_List: GT_Action_List{GT_Action: "" + v_Action},
			Attribute_List: j.Attribute_List,
		})
	}
	return
}

func parse_cDB_AB_create_Set(ab_name _Name, sa *Attribute_List) (ok bool) {
	switch _, flag := i_ab[ab_name]; flag {
	case true:
		log.Debugf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:           _Type_set,
		IPPrefix:       netip.Prefix{},
		FQDN:           "",
		Set:            map[_Name]i_AB_Set{},
		GT_Action_List: GT_Action_List{GT_Action: "set security address-book global address-set " + ab_name.String()},
		Attribute_List: *sa,
	}
	return true
}
func parse_cDB_AB_add_Address(public, private bool, ab_name _Name, inbound ...interface{}) (ok bool) {
	var (
		interim []interface{}
	)
	for _, address := range inbound {
		switch value := (address).(type) {
		case netip.Addr:
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
			case true:
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
			var (
				bits = 32
			)
			switch value.Is6() {
			case true:
				bits = 128
			}
			interim = append(interim, parse_interface(value.Prefix(bits)).(netip.Prefix))
		case netip.Prefix:
			switch is_private, is_valid := value.Masked().Addr().IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
			case true:
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
			interim = append(interim, value)
		case _FQDN:
			switch len(value) == 0 {
			case true:
				continue
			}
			interim = append(interim, value)
		case _Name:
			switch len(value) == 0 {
			case true:
				continue
			}
			interim = append(interim, value)
		default:
			log.Warnf("AB '%v', address '%v'; unknown address type; ACTION: skip.", ab_name, value)
			continue
		}
	}

	for _, address := range interim {
		switch _, flag := i_ab[ab_name]; {
		case flag && i_ab[ab_name].Type == _Type_set:
			switch value := (address).(type) {
			case _Name:
				ok = true
				i_ab[ab_name].Set[value] = i_AB_Set{
					Type:           _Type_set,
					GT_Action_List: GT_Action_List{GT_Action: " address-set " + value.String()},
					Attribute_List: Attribute_List{},
				}
			case _FQDN:
				ok = true
				i_ab[ab_name].Set[_Name(value)] = i_AB_Set{
					Type:           _Type_fqdn,
					GT_Action_List: GT_Action_List{GT_Action: " address " + value.String()},
					Attribute_List: Attribute_List{},
				}
				parse_cDB_AB_add_Address(true, true, _Name(value), value)
			case netip.Prefix:
				ok = true
				i_ab[ab_name].Set[_Name(value.String())] = i_AB_Set{
					Type:           _Type_ipprefix,
					GT_Action_List: GT_Action_List{GT_Action: " address " + value.String()},
					Attribute_List: Attribute_List{},
				}
				parse_cDB_AB_add_Address(true, true, _Name(value.String()), value)
			}
		case flag:
			log.Debugf("AB '%+v''%+v', already exist; ACTION: skip.", ab_name, i_ab[ab_name])
			continue
		default:
			switch value := (address).(type) {
			case _FQDN:
				ok = true
				i_ab[ab_name] = &i_AB{
					Type:           _Type_fqdn,
					IPPrefix:       netip.Prefix{},
					FQDN:           value,
					Set:            nil,
					GT_Action_List: GT_Action_List{GT_Action: "set security address-book global address " + ab_name.String() + " dns-name " + value.String()},
					Attribute_List: Attribute_List{},
				}
			case netip.Prefix:
				ok = true
				i_ab[ab_name] = &i_AB{
					Type:           _Type_ipprefix,
					IPPrefix:       value,
					FQDN:           "",
					Set:            nil,
					GT_Action_List: GT_Action_List{GT_Action: "set security address-book global address " + ab_name.String() + " address " + value.String()},
					Attribute_List: Attribute_List{},
				}
			}
		}
	}
	return
}

func parse_cDB_Peer_add_IF(peer *cDB_Peer, v_Peer *i_Peer) {
	return
}

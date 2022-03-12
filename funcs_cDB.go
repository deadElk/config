package main

import (
	"net/netip"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func parse_cDB(xml_db *cDB) (ok bool) {
	log.SetLevel(xml_db.Verbosity)
	_Settings[_group] = _Name(xml_db.XMLName.Local)
	switch {
	case len(xml_db.GT_Path) != 0:
		_Settings[_dirname_GT] = xml_db.GT_Path
	}
	switch {
	case !read_GT():
		log.Warnf("templates read error; ACTION: skip.")
		return
	}
	set_VI_IPPrefix(xml_db.VI_IPPrefix)
	set_Domain_Name(xml_db.Domain_Name)
	_Settings[_GT_list] = []_Name{}
	for _, b := range re_period.Split(xml_db.GT_List, -1) {
		_Settings[_GT_list] = append(_Settings[_GT_list].([]_Name), _Name(b))
	}
	switch {
	case len(xml_db.Upload_Path) != 0:
		_Settings[_dirname_out] = xml_db.Upload_Path
	}
	parse_cDB_AB_create_Set(_Name_PUBLIC, &_Attribute_List{})

	parse_cDB_AB(xml_db.AB)
	parse_cDB_JA(xml_db.JA)
	parse_cDB_PL(xml_db.PL)

	define_iDB_PS()
	parse_cDB_PS(xml_db.PS)
	parse_cDB_Peer(xml_db.Peer)
	parse_cDB_VI(xml_db.VI)

	return true
}

func parse_cDB_AB(inbound []*cDB_AB) (ok bool) {
	for _, b := range inbound {
		switch {
		case b.Set:
			switch {
			case !parse_cDB_AB_create_Set(b.Name, &b._Attribute_List):
				continue
			}
		}
		for _, d := range b.Address {
			parse_cDB_AB_add_Address(true, true, b.Name, d.AB, d.FQDN, d.IPPrefix)
		}
	}
	return true
}
func parse_cDB_JA(inbound []*cDB_JA) (ok bool) {
	for _, b := range inbound {
		switch _, flag := i_ja[b.Name]; {
		case flag:
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
							GT_Action:        strings_join(" ", _Action_term, d.Name, _Action_protocol, d.Protocol, _Action_destination__port, d.Destination_Port),
							_Attribute_List:  d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       strings_join(" ", _Action_applications____application, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
	return true
}
func parse_cDB_PL(inbound []*cDB_PO_PL) (ok bool) {
	for _, b := range inbound {
		switch _, flag := i_pl[b.Name]; {
		case flag:
			log.Debugf("Policy List '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_pl[b.Name] = func() (outbound *i_PO_PL) {
			outbound = &i_PO_PL{
				Match: func() (outbound []i_PO_PL_Match) {
					for _, d := range b.Match {
						switch {
						case !d.IPPrefix.IsValid():
							log.Warnf("Policy List '%v', invalid IP '%v'; ACTION: skip.", b.Name, d.IPPrefix.String())
						}
						outbound = append(outbound, i_PO_PL_Match{
							IPPrefix:        d.IPPrefix,
							GT_Action:       d.IPPrefix.String(),
							_Attribute_List: d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       strings_join(" ", _Action_policy__options___prefix__list, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
	return true
}
func parse_cDB_PS(inbound []*cDB_PO_PS) (ok bool) {
	for _, b := range inbound {
		switch _, flag := i_ps[b.Name]; {
		case flag:
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
									outbound = append(outbound, i_PO_PS_From{
										RI:         f.RI,
										Protocol:   f.Protocol,
										Route_Type: f.Route_Type,
										PL:         f.PL,
										Mask:       f.Mask,
										GT_Action: strings_join(" ", _Action_from,
											f.RI.action_RI(nil, nil, _Type_policy_statement, ""),
											f.Protocol.action_Protocol(nil, nil, "", ""),
											f.Route_Type.action_Route_Type(nil, nil, "", ""),
											f.PL.action_PL(nil, nil, _Type_policy_statement, ""),
											f.Mask,
										),
										_Attribute_List: f._Attribute_List,
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
										v_Action = strings_join(" ", _Action_metric, f.Metric)
									}
									outbound = append(outbound, i_PO_PS_Then{
										Action:          f.Action,
										Action_Flag:     f.Action_Flag,
										Metric:          f.Metric,
										GT_Action:       strings_join(" ", _Action_then, f.Action, f.Action_Flag, v_Action),
										_Attribute_List: f._Attribute_List,
									})
								}
								return
							}(),
							GT_Action:       strings_join(" ", _Action_term, d.Name),
							_Attribute_List: d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       strings_join(" ", _Action_policy__options___policy__statement, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
	return true
}
func parse_cDB_Peer(inbound []*cDB_Peer) (ok bool) {
	for _, b := range inbound {
		switch _, flag := i_peer[b.ASN]; {
		case flag:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		}
		parse_cDB_AB(b.AB)
		parse_cDB_JA(b.JA)
		parse_cDB_PL(b.PL)
		parse_cDB_PS(b.PS)
	}
	for _, b := range inbound {
		switch _, flag := i_peer[b.ASN]; {
		case flag:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		}
		var (
			v_Peer = &i_Peer{
				ASN:          b.ASN,
				PName:        pad(&b.ASN, 10),
				Router_ID:    netip.Addr{},
				IF_2_RI:      map[_Name]_Name{},
				VI:           map[_VI_ID]*i_VI{},
				VI_Local:     map[_VI_ID]*i_VI_Peer{},
				VI_Remote:    map[_VI_ID]*i_VI_Peer{},
				VI_GT:        map[_VI_ID]*i_VI_GT{},
				IFM:          map[_Name]i_Peer_IFM{},
				RI:           map[_Name]i_Peer_RI{},
				Hostname:     "",
				Domain_Name:  "",
				Version:      b.Version,
				Major:        0,
				Manufacturer: b.Manufacturer,
				Model:        b.Model,
				Serial:       b.Serial,
				Root:         b.Root.validate(16),
				GT_List:      []_Name{},
				SZ:           map[_Name]i_Peer_SZ{},
				NAT:          map[_Type]i_Peer_NAT_Type{},
				AB:           map[_Name]*i_AB{},
				JA:           map[_Name]*i_JA{},
				PL:           map[_Name]*i_PO_PL{},
				PS:           map[_Name]*i_PO_PS{},
				SP: i_Peer_SP{
					Option_List: _SP_Option_List{},
					Exact:       nil,
					Global:      nil,
					GT_Action:   "",
				},
				FW:               nil,
				_IKE_Option_List: _IKE_Option_List{},
				GT_Action:        "",
				_Attribute_List:  b._Attribute_List,
			}
		)
		parse_cDB_AB_create_Set(_Name(strings_join("", "O_AS", v_Peer.PName)), &_Attribute_List{})
		parse_cDB_AB_create_Set(_Name(strings_join("", "I_AS", v_Peer.PName)), &_Attribute_List{})
		v_Peer.link_AB(_Name_PUBLIC, _Name(strings_join("", "O_AS", v_Peer.PName)), _Name(strings_join("", "I_AS", v_Peer.PName)))
		parse_cDB_Peer_Version(b, v_Peer)
		v_Peer._IKE_Option_List.IKE_GCM = v_Peer.Major >= 12.3
		parse_cDB_Peer_RI(b, v_Peer)

		// PName
		parse_cDB_Peer_Router_ID(b, v_Peer)
		// IF_2_RI
		// VI
		// VI_Local
		// VI_Remote
		parse_cDB_Peer_IFM(b, v_Peer)
		// RI
		parse_cDB_Peer_Hostname(b, v_Peer)
		parse_cDB_Peer_Domain_Name(b, v_Peer)
		// Version
		// Major
		// Manufacturer
		// Model
		// Serial
		// Root
		parse_cDB_Peer_GT_List(b, v_Peer)
		parse_cDB_Peer_SZ(b, v_Peer)
		parse_cDB_Peer_NAT(b, v_Peer)
		parse_cDB_Peer_SP(b, v_Peer)
		parse_cDB_Peer_FW(b, v_Peer)

		i_peer[b.ASN] = v_Peer
		ok = true

	}
	return
}
func parse_cDB_VI(inbound []*cDB_VI) (ok bool) {
	for _, b := range inbound {
		switch _, flag := i_vi[b.ID]; {
		case flag:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ID)
			continue
		}
		var (
			v_vi_peer_list = make(map[_VI_Peer_ID]*i_VI_Peer)
			v_IKE_GCM      = true
			v_IKE_No_NAT   = true
		)
		i_vi[b.ID] = &i_VI{
			PName:         pad(&b.ID, 5),
			IPPrefix:      get_VI_IPPrefix(b.ID, 0).Masked(),
			Type:          _Type_st,
			Communication: b.Communication,
			Route_Metric: func() _Route_Weight {
				switch {
				case b.Route_Metric > _Route_Weight_max_rm:
					return 0
				}
				return _Route_Weight_max_rm - b.Route_Metric
			}(),
			PSK: b.PSK.validate(64),
			// _IKE_Option_List: &_IKE_Option_List{
			IKE_GCM:    v_IKE_GCM,
			IKE_No_NAT: v_IKE_No_NAT,
			// },
			GT_Action:       "",
			_Attribute_List: b._Attribute_List,
		}
		i_vi_peer[b.ID] = map[_VI_Peer_ID]*i_VI_Peer{}

		for _, d := range b.Peer {
			switch {
			case d.ID > 1:
				log.Warnf("VI '%v', Peer '%v', index out of range; ACTION: skip.", b.ID, d.ID)
				continue
			}
			switch _, flag := i_vi_peer[b.ID][d.ID]; {
			case flag:
				log.Warnf("VI '%v', Peer '%v' already exist; ACTION: skip.", b.ID, d.ID)
				continue
			}
			var (
				v_RI                = d.RI.validate_RI(_Settings[_mgmt_RI].(_Name))
				v_IF                _Name
				v_IP                netip.Addr
				v_NAT               netip.Addr
				v_IKE_Local_Address bool
				v_IKE_Dynamic       bool
				v_Inner_RI          = d.Inner_RI.validate_RI(_Settings[_mgmt_RI].(_Name))
			)
			switch _, flag := i_peer[d.ASN].RI[v_RI].IF[d.IF]; {
			case len(d.IF) == 0:
				for v_IF = range i_peer[d.ASN].RI[v_RI].IF {
					log.Debugf("VI '%v', Peer '%v', taken first found interface '%v'; ACTION: skip.", b.ID, d.ID, v_IF)
					break
				}
			case flag:
				v_IF = d.IF
			}
			switch {
			case len(i_peer[d.ASN].RI[v_RI].IF[v_IF].IP) < 1:
				log.Warnf("VI '%v', Peer '%v', IF '%v' no ip addresses found; ACTION: skip.", b.ID, d.ID, v_IF)
				continue
			}
			i_peer[d.ASN].SZ[v_RI].IF[v_IF]._Host_Inbound_Traffic_List.Services[_Service_ike] = true
			v_IP, v_NAT = func() (outbound, outbound_nat netip.Addr) {
				var (
					interim netip.Prefix
					value   i_Peer_RI_IF_IP
				)
				for interim, value = range i_peer[d.ASN].RI[v_RI].IF[v_IF].IP {
					switch {
					case interim.Addr() == d.IP:
						return interim.Addr(), value.NAT
					}
				}
				switch {
				case !interim.IsValid() && !i_peer[d.ASN].RI[v_RI].IF[v_IF].IP[interim].DHCP:
					log.Warnf("VI '%v', Peer '%v', IF '%v' no valid ip addresses found; ACTION: try to find something.", b.ID, d.ID, v_IF)
				}
				return interim.Addr(), value.NAT
			}()
			switch {
			case len(i_peer[d.ASN].RI[v_RI].IF[v_IF].IP) > 1:
				v_IKE_Local_Address = true
			case (!v_IP.IsValid() || v_IP.IsPrivate()) && (!v_NAT.IsValid() || v_NAT.IsPrivate()):
				i_vi[b.ID].IKE_No_NAT = false
			}

			i_vi_peer[b.ID][d.ID] = &i_VI_Peer{
				ASN:               d.ASN,
				RI:                v_RI,
				IF:                v_IF,
				IP:                v_IP,
				NAT:               v_NAT,
				Hub:               d.Hub,
				Inner_RI:          v_Inner_RI,
				Inner_IP:          get_VI_IPPrefix(b.ID, d.ID+1).Addr(),
				Inner_IPPrefix:    get_VI_IPPrefix(b.ID, d.ID+1),
				IKE_Local_Address: v_IKE_Local_Address,
				IKE_Dynamic:       v_IKE_Dynamic,
				// _IKE_Option_List:   i_vi[b.ID]._IKE_Option_List,
				GT_Action:       "",
				_Attribute_List: d._Attribute_List,
			}
			v_vi_peer_list[d.ID] = i_vi_peer[b.ID][d.ID]
		}

		var (
			_first, _second _VI_Peer_ID
			_total          = _VI_Peer_ID(len(v_vi_peer_list))
			_if             = _Name(strings_join(".", _Name_st0, b.ID))
		)
		switch {
		case _total != 2:
			continue
		}

		for _first, _second = 0, _total-1; _first <= _total-1; _first, _second = _first+1, _second-1 {

			i_vi[b.ID].IKE_GCM = i_vi[b.ID].IKE_GCM && i_peer[v_vi_peer_list[_first].ASN].IKE_GCM

			i_peer[v_vi_peer_list[_first].ASN].VI[b.ID] = i_vi[b.ID]
			i_peer[v_vi_peer_list[_first].ASN].VI_Local[b.ID] = i_vi_peer[b.ID][_first]
			i_peer[v_vi_peer_list[_first].ASN].VI_Remote[b.ID] = i_vi_peer[b.ID][_second]

			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = i_Peer_RI_IF{
				IFM:           _Name_st0,
				IFsM:          _Name(b.ID.String()),
				Communication: _Settings[_comm_vi].(_Communication),
				IP: map[netip.Prefix]i_Peer_RI_IF_IP{
					i_vi_peer[b.ID][_first].Inner_IPPrefix: {
						Masked:          i_vi_peer[b.ID][_first].Inner_IPPrefix.Masked(),
						Primary:         false,
						Preferred:       false,
						NAT:             netip.Addr{},
						DHCP:            false,
						GT_Action:       "",
						_Attribute_List: _Attribute_List{},
					},
				},
				PARP:            nil,
				GT_Action:       "",
				_Attribute_List: _Attribute_List{Description: _Description(strings_join("_", i_vi_peer[b.ID][_first].IF, "AS"+pad(i_vi_peer[b.ID][_second].ASN, 10), i_vi_peer[b.ID][_second].IF))},
			}
			i_peer[v_vi_peer_list[_first].ASN].SZ[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = i_Peer_SZ_IF{
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh, _Protocol_bgp),
				GT_Action:                  strings_join(" ", _Action_interfaces, _if),
				_Attribute_List:            _Attribute_List{},
			}
			i_peer[v_vi_peer_list[_first].ASN].IF_2_RI[_if] = i_vi_peer[b.ID][_first].Inner_RI
			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].IP_2_IF[i_vi_peer[b.ID][_first].Inner_IP] = _if
		}

		for _first, _second = 0, _total-1; _first <= _total-1; _first, _second = _first+1, _second-1 {
			i_peer[v_vi_peer_list[_first].ASN].VI_GT[b.ID] = &i_VI_GT{
				PName:                    i_vi[b.ID].PName,
				IPPrefix:                 i_vi[b.ID].IPPrefix,
				Type:                     i_vi[b.ID].Type,
				Communication:            i_vi[b.ID].Communication,
				Route_Metric:             i_vi[b.ID].Route_Metric,
				PSK:                      i_vi[b.ID].PSK,
				IKE_GCM:                  i_vi[b.ID].IKE_GCM,
				IKE_No_NAT:               i_vi[b.ID].IKE_No_NAT,
				Local_ASN:                i_vi_peer[b.ID][_first].ASN,
				Local_RI:                 i_vi_peer[b.ID][_first].RI,
				Local_IF:                 i_vi_peer[b.ID][_first].IF,
				Local_IP:                 i_vi_peer[b.ID][_first].IP,
				Local_NAT:                i_vi_peer[b.ID][_first].NAT,
				Local_Hub:                i_vi_peer[b.ID][_first].Hub,
				Local_Inner_RI:           i_vi_peer[b.ID][_first].Inner_RI,
				Local_Inner_IP:           i_vi_peer[b.ID][_first].Inner_IP,
				Local_Inner_IPPrefix:     i_vi_peer[b.ID][_first].Inner_IPPrefix,
				Local_IKE_Local_Address:  i_vi_peer[b.ID][_first].IKE_Local_Address,
				Local_IKE_Dynamic:        i_vi_peer[b.ID][_first].IKE_Dynamic,
				Remote_ASN:               i_vi_peer[b.ID][_second].ASN,
				Remote_RI:                i_vi_peer[b.ID][_second].RI,
				Remote_IF:                i_vi_peer[b.ID][_second].IF,
				Remote_IP:                i_vi_peer[b.ID][_second].IP,
				Remote_NAT:               i_vi_peer[b.ID][_second].NAT,
				Remote_Hub:               i_vi_peer[b.ID][_second].Hub,
				Remote_Inner_RI:          i_vi_peer[b.ID][_second].Inner_RI,
				Remote_Inner_IP:          i_vi_peer[b.ID][_second].Inner_IP,
				Remote_Inner_IPPrefix:    i_vi_peer[b.ID][_second].Inner_IPPrefix,
				Remote_IKE_Local_Address: i_vi_peer[b.ID][_second].IKE_Local_Address,
				Remote_IKE_Dynamic:       i_vi_peer[b.ID][_second].IKE_Dynamic,
				GT_Action:                "",
				_Attribute_List:          _Attribute_List{},
			}
			switch _, flag := i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[_Settings[_group].(_Name)]; {
			case !flag:
				i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[_Settings[_group].(_Name)] = _BGP_Group{
					Local_ASN:  0,
					Remote_ASN: 0,
					Passive:    false,
					Neighbor:   map[netip.Addr]_BGP_Group_Neighbor{},
					GT_Action:  strings_join(" ", _Action_group, _Settings[_group]),
				}
			}
			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[_Settings[_group].(_Name)].Neighbor[i_vi_peer[b.ID][_second].Inner_IP] = _BGP_Group_Neighbor{
				Local_ASN:  i_vi_peer[b.ID][_first].ASN,
				Remote_ASN: i_vi_peer[b.ID][_second].ASN,
				Passive:    i_vi_peer[b.ID][_first].Hub,
				Local_IP:   i_vi_peer[b.ID][_first].Inner_IP,
				Route_Leak: parse_iDB_Route_Leak(nil, i_peer[v_vi_peer_list[_first].ASN], "", "", &map[_Action]i_Route_Leak_FromTo{
					_Action_import: {PS: []_Name{0: _Name(strings_join("_", _Action_import_metric, pad(i_vi[b.ID].Route_Metric, 2)))}},
					_Action_export: {PS: []_Name{0: _Name(_Action_aggregate), 1: _Name(strings_join("_", _Action_export_metric, pad(i_vi[b.ID].Route_Metric, 2)))}},
				}),
				GT_Action:       strings_join(" ", _Action_neighbor, i_vi_peer[b.ID][_second].Inner_IP),
				_Attribute_List: _Attribute_List{Description: _Description(strings_join("", "TI", i_vi[b.ID].PName))},
			}
		}
	}
	return true
}

func parse_cDB_Peer_Router_ID(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	switch {
	case peer.Router_ID.IsValid():
		v_Peer.Router_ID = peer.Router_ID
	default:
		v_Peer.Router_ID = func() netip.Addr {
			for a := range v_Peer.RI[_Settings[_RI].(_Name)].IF[_Name_lo0_0].IP {
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
			GT_Action:       strings_join(" ", _Action_interfaces, b.Name),
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
		parse_cDB_PS([]*cDB_PO_PS{
			0: {Name: _Name(strings_join("_", _Action_redistribute, b.Name)),
				Term: []cDB_PO_PS_Term{
					// 0: {Name: empty_Name.next_ID(),
					0: {Name: "PERMIT",
						From:            []cDB_PO_PS_From{0: {RI: b.Name, _Attribute_List: _Attribute_List{}}},
						Then:            []cDB_PO_PS_Then{0: {Action: _Action_accept, _Attribute_List: _Attribute_List{}}},
						_Attribute_List: _Attribute_List{},
					},
				},
				_Attribute_List: _Attribute_List{},
			},
		})
		v_Peer.link_PS(_Name(strings_join("_", _Action_redistribute, b.Name)))
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
								parse_cDB_AB_add_Address(true, false, _Name_PUBLIC, f.IPPrefix.Addr(), f.NAT)
								parse_cDB_AB_add_Address(true, false, _Name(strings_join("", "O_AS", v_Peer.PName)), f.IPPrefix, f.NAT)
								parse_cDB_AB_add_Address(false, true, _Name(strings_join("", "I_AS", v_Peer.PName)), f.IPPrefix, f.NAT)
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
								parse_cDB_AB_add_Address(true, false, _Name_PUBLIC, f.IP, f.NAT)
								outbound[f.IP] = i_Peer_RI_IF_PARP{
									NAT:             f.NAT,
									GT_Action:       strings_join(" ", _Action_security___nat___proxy__arp),
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
									v_RT_Action      = f.Action.validate(nil, v_Peer)
									v_RT_Action_Flag _Action
									v_Action         = strings_join(" ", _Action_static___route, d.Identifier)
								)
								switch {
								case v_RT_Action == _Action_discard:
									v_Action = strings_join(" ", v_Action, v_RT_Action)
								case v_RT_Action == _Action_next__table && len(f.Table) != 0:
									v_RT_Table = f.Table
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_Table)
								case (v_RT_Action == _Action_next__hop || v_RT_Action == _Action_qualified__next__hop) && len(f.IF) != 0:
									v_RT_IF = f.IF
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IF)
								case (v_RT_Action == _Action_next__hop || v_RT_Action == _Action_qualified__next__hop) && f.IP.IsValid():
									v_RT_IP = f.IP
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IP)
								case len(v_RT_Action) == 0 && len(f.Table) != 0:
									v_RT_Action = _Action_next__table
									v_RT_Table = f.Table
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_Table)
								case len(v_RT_Action) == 0 && len(f.IF) != 0:
									v_RT_Action = _Action_next__hop
									v_RT_IF = f.IF
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IF)
								case len(v_RT_Action) == 0 && f.IP.IsValid():
									v_RT_Action = _Action_next__hop
									v_RT_IP = f.IP
									v_Action = strings_join(" ", v_Action, v_RT_Action, v_RT_IP)
								case len(v_RT_Action) == 0:
									v_RT_Action = _Action_discard
									v_Action = strings_join(" ", v_Action, v_RT_Action)
								default:
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', invalid GW '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Identifier, f)
									continue
								}
								switch {
								case f.Metric > 0:
									v_Action = strings_join(" ", v_Action, _Action_metric, f.Metric)
									fallthrough
								case f.Preference > 0:
									v_Action = strings_join(" ", v_Action, _Action_preference, f.Preference)
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
				case b.Name != _Settings[_RI].(_Name):
					return strings_join(" ", _Action_routing__instances, b.Name)
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
			BGP:             _BGP{BGP_Group: map[_Name]_BGP_Group{}, GT_Action: strings_join(" ", _Action_protocols___bgp), _Attribute_List: _Attribute_List{}},
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
		v_Peer.Domain_Name = _Settings[_domain_name].(_FQDN)
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
		v_Peer.GT_List = _Settings[_GT_list].([]_Name)
	}
	return true
}
func parse_cDB_Peer_SZ(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	for _, b := range peer.SZ {
		switch {
		case b.Name == _Settings[_mgmt_RI].(_Name):
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
						GT_Action:                  strings_join(" ", _Action_interfaces, c),
						_Attribute_List:            _Attribute_List{},
					}
				}
				return
			}(),
			_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
			GT_Action:                  strings_join(" ", _Action_security__zones___security__zone, b.Name),
			_Attribute_List:            b._Attribute_List,
		}
	}
	for a := range v_Peer.RI {
		switch a {
		case _Settings[_mgmt_RI].(_Name):
			continue
		}
		switch _, flag := v_Peer.SZ[a]; {
		case !flag:
			v_Peer.SZ[a] = i_Peer_SZ{
				Screen:                     "",
				IF:                         map[_Name]i_Peer_SZ_IF{},
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
				GT_Action:                  strings_join(" ", _Action_security__zones___security__zone, a),
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
				GT_Action:                  strings_join(" ", _Action_interfaces, e),
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
		GT_Action:          strings_join(" ", _Action_security___nat___source),
		_Attribute_List:    h._Attribute_List,
	}

	h = peer.NAT_Destination

	v_Peer.NAT[_Type_destination] = i_Peer_NAT_Type{
		Pool:            parse_cDB_Pool(peer, v_Peer, _Type_destination, _Type_pool, &h.Pool),
		Rule_Set:        parse_cDB_Rule_Set(peer, v_Peer, _Type_destination, "", &h.Rule_Set),
		GT_Action:       strings_join(" ", _Action_security___nat___destination),
		_Attribute_List: h._Attribute_List,
	}

	h = peer.NAT_Static

	v_Peer.NAT[_Type_static] = i_Peer_NAT_Type{
		Pool:            parse_cDB_Pool(peer, v_Peer, _Type_static, _Type_pool, &h.Pool),
		Rule_Set:        parse_cDB_Rule_Set(peer, v_Peer, _Type_static, "", &h.Rule_Set),
		GT_Action:       strings_join(" ", _Action_security___nat___static),
		_Attribute_List: h._Attribute_List,
	}
	return true
}
func parse_cDB_Peer_SP(peer *cDB_Peer, v_Peer *i_Peer) (ok bool) {
	v_Peer.SP.Option_List = _SP_Option_List{
		Default_Policy: func() _Action {
			switch value := peer.SP_Option_List.Default_Policy; value {
			case _Action_permit__all, _Action_deny__all:
				return value
			case "":
				return _Settings[_sp_default_policy].(_Action)
			default:
				log.Warnf("Peer '%v', unknown default security policy '%v'; ACTION: use '%v'.", peer.ASN, value, _Settings[_sp_default_policy])
				return _Settings[_sp_default_policy].(_Action)
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
				t.GT_Action = strings_join(" ", _Action_security___policies, _Action_from__zone, t.From[0].SZ, _Action_to__zone, t.To[0].SZ)
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
			GT_Action:       strings_join(" ", _Action_security___policies___global___policy, j.Name),
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
									GT_Action:       strings_join(" ", _Action_then, f.Action, f.Action_Flag, f.RI.action_RI(peer, v_Peer, _Type_firewall, _Type_then)),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						GT_Action:       strings_join(" ", _Action_term, d.Name),
						_Attribute_List: d._Attribute_List,
					})
				}
				return
			}(),
			GT_Action:       strings_join(" ", _Action_firewall___filter, b.Name),
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
			GT_Action:       strings_join(" ", _Action_rule__set, j.Name),
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

func parse_cDB_AB_create_Set(ab_name _Name, sa *_Attribute_List) (ok bool) {
	switch _, flag := i_ab[ab_name]; {
	case flag:
		log.Debugf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = &i_AB{
		Type:            _Type_set,
		IPPrefix:        netip.Prefix{},
		FQDN:            "",
		Set:             map[_Name]i_AB_Set{},
		GT_Action:       strings_join(" ", _Action_security___address__book___global___address__set, ab_name),
		_Attribute_List: *sa,
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
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); {
			case !is_valid || (is_private && !private) || (!is_private && !public):
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
			var (
				bits = 32
			)
			switch {
			case value.Is6():
				bits = 128
			}
			interim = append(interim, parse_interface(value.Prefix(bits)).(netip.Prefix))
		case netip.Prefix:
			switch is_private, is_valid := value.Masked().Addr().IsPrivate(), value.IsValid(); {
			case !is_valid || (is_private && !private) || (!is_private && !public):
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
			interim = append(interim, value)
		case _FQDN:
			switch {
			case len(value) == 0:
				continue
			}
			interim = append(interim, value)
		case _Name:
			switch {
			case len(value) == 0:
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
					Type:            _Type_set,
					GT_Action:       strings_join(" ", _Action_address__set, value),
					_Attribute_List: _Attribute_List{},
				}
			case _FQDN:
				ok = true
				i_ab[ab_name].Set[_Name(value)] = i_AB_Set{
					Type:            _Type_fqdn,
					GT_Action:       strings_join(" ", _Action_address, value),
					_Attribute_List: _Attribute_List{},
				}
				parse_cDB_AB_add_Address(true, true, _Name(value), value)
			case netip.Prefix:
				ok = true
				i_ab[ab_name].Set[_Name(value.String())] = i_AB_Set{
					Type:            _Type_ipprefix,
					GT_Action:       strings_join(" ", _Action_address, value),
					_Attribute_List: _Attribute_List{},
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
					Type:            _Type_fqdn,
					IPPrefix:        netip.Prefix{},
					FQDN:            value,
					Set:             nil,
					GT_Action:       strings_join(" ", _Action_security___address__book___global___address, ab_name, _Action_dns__name, value),
					_Attribute_List: _Attribute_List{},
				}
			case netip.Prefix:
				ok = true
				i_ab[ab_name] = &i_AB{
					Type:            _Type_ipprefix,
					IPPrefix:        value,
					FQDN:            "",
					Set:             nil,
					GT_Action:       strings_join(" ", _Action_security___address__book___global___address, ab_name, _Action_address, value),
					_Attribute_List: _Attribute_List{},
				}
			}
		}
	}
	return
}

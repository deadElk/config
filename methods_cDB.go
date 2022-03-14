package main

import (
	"net/netip"
	"net/url"

	log "github.com/sirupsen/logrus"
)

func (inbound cDB_List) parse() {
	define_iDB_Vocabulary()
	var (
		s = make(map[_Name]bool)
	)
	for _, b := range inbound {
		log.SetLevel(b.Verbosity)
		_S_group = _Name(b.XMLName.Local)
		set_VI_IPPrefix(b.VI_IPPrefix)
		b.Domain_Name.set_Domain_Name()
		for _, d := range re_period.Split(b.GT_List, -1) {
			switch _, flag := s[_Name(d)]; {
			case flag:
				continue
			}
			s[_Name(d)] = true
			_S_GT_List = append(_S_GT_List, _Name(d))
		}
		b.AB.parse()
		b.JA.parse()
		b.PL.parse()
		b.PS.parse()
	}
	for _, b := range inbound {
		b.Peer.parse()
	}
	for _, b := range inbound {
		b.VI.parse()
	}
	for _, b := range inbound {
		b.LDAP.parse()
	}
}

func (inbound cDB_AB_List) parse() {
	for _, b := range inbound {
		switch {
		case b.Set:
			switch {
			case !create_iDB_AB_Set(b.Name):
				continue
			}
		}
		for _, d := range b.Address {
			add_iDB_AB_Address_List(true, true, b.Name, d.AB, d.FQDN, d.IPPrefix)
		}
	}
}
func (inbound cDB_JA_List) parse() {
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
							GT_Action:        strings_join(" ", _W_term, d.Name, _W_protocol, d.Protocol, _W_destination__port, d.Destination_Port),
							_Attribute_List:  d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       strings_join(" ", _W_applications____application, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
}
func (inbound cDB_PO_PL_List) parse() {
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
				GT_Action:       strings_join(" ", _W_policy__options___prefix__list, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
}
func (inbound cDB_PO_PS_List) parse() {
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
										GT_Action: strings_join(" ", _W_from,
											f.RI.action_RI(nil, nil, _Type_policy__statement, ""),
											f.Protocol.action_Protocol(nil, nil, "", ""),
											f.Route_Type.action_Route_Type(nil, nil, "", ""),
											f.PL.action_PL(nil, nil, _Type_policy__statement, ""),
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
										v_Action = strings_join(" ", _W_metric, f.Metric)
									}
									outbound = append(outbound, i_PO_PS_Then{
										Action:          f.Action,
										Action_Flag:     f.Action_Flag,
										Metric:          f.Metric,
										GT_Action:       strings_join(" ", _W_then, f.Action, f.Action_Flag, v_Action),
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
				GT_Action:       strings_join(" ", _W_policy__options___policy__statement, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
}
func (inbound cDB_Peer_List) parse() {
	for _, b := range inbound {
		switch _, flag := i_peer[b.ASN]; {
		case flag:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		}
		b.AB.parse()
		b.JA.parse()
		b.PL.parse()
		b.PS.parse()
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
				ASName:       _Name(strings_join("", _Name_AS, pad(b.ASN, 10))),
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
		create_iDB_AB_Set(_Name(strings_join("", "O_AS", v_Peer.PName)))
		create_iDB_AB_Set(_Name(strings_join("", "I_AS", v_Peer.PName)))
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
		i_peer_list = append(i_peer_list, b.ASN)

	}
}
func (inbound cDB_VI_List) parse() {
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
				v_RI                = d.RI.validate_RI(_S_mgmt_RI)
				v_IF                _Name
				v_IP                netip.Addr
				v_NAT               netip.Addr
				v_IKE_Local_Address bool
				v_IKE_Dynamic       bool
				v_Inner_RI          = d.Inner_RI.validate_RI(_S_mgmt_RI)
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
				Communication: _S_Comm[_comm_vi],
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
				_Attribute_List: _Attribute_List{Description: _Description(strings_join("_", i_vi_peer[b.ID][_first].IF, i_peer[v_vi_peer_list[_second].ASN].ASName, i_vi_peer[b.ID][_second].IF))},
			}
			i_peer[v_vi_peer_list[_first].ASN].SZ[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = i_Peer_SZ_IF{
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh, _Protocol_bgp),
				GT_Action:                  strings_join(" ", _W_interfaces, _if),
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
			switch _, flag := i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[_S_group]; {
			case !flag:
				i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[_S_group] = _BGP_Group{
					Local_ASN:  0,
					Remote_ASN: 0,
					Passive:    false,
					Neighbor:   map[netip.Addr]_BGP_Group_Neighbor{},
					GT_Action:  strings_join(" ", _W_group, _S_group),
				}
			}
			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[_S_group].Neighbor[i_vi_peer[b.ID][_second].Inner_IP] = _BGP_Group_Neighbor{
				Local_ASN:  i_vi_peer[b.ID][_first].ASN,
				Remote_ASN: i_vi_peer[b.ID][_second].ASN,
				Passive:    i_vi_peer[b.ID][_first].Hub,
				Local_IP:   i_vi_peer[b.ID][_first].Inner_IP,
				Route_Leak: parse_iDB_Route_Leak(nil, i_peer[v_vi_peer_list[_first].ASN], "", "", map[_W]*i_Route_Leak_FromTo{
					_W_import: {PS: []_Name{0: _Name(strings_join("_", _W_import_metric, pad(i_vi[b.ID].Route_Metric, 2)))}},
					_W_export: {PS: []_Name{0: _Name(_W_aggregate), 1: _Name(strings_join("_", _W_export_metric, pad(i_vi[b.ID].Route_Metric, 2)))}},
				}),
				GT_Action:       strings_join(" ", _W_neighbor, i_vi_peer[b.ID][_second].Inner_IP),
				_Attribute_List: _Attribute_List{Description: _Description(strings_join("", "TI", i_vi[b.ID].PName))},
			}
		}
	}
}
func (inbound cDB_LDAP_List) parse() {
	for _, b := range inbound {
		var (
			a = parse_interface(url.Parse(b.URL)).(*url.URL)
		)
		switch _, flag := i_ldap[a]; {
		case flag:
			log.Warnf("LDAP '%v' already defined; ACTION: skip.", a)
		}
		i_ldap[a] = i_LDAP{}
	}
}

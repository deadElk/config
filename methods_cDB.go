package main

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func (receiver cDB_N_List) parse() (status bool) { // parse everything in order of dependency.
	for _, b := range receiver {
		switch {
		case b.Reserved:
			continue
		}
		b.AB.parse()
		b.JA.parse()
		b.PL.parse()
		b.PS.parse()
		b.Peer.parse_Vocabulary()
	}
	for _, b := range receiver {
		b.parse()
	}
	for _, b := range receiver {
		switch {
		case b.Reserved:
			continue
		}
		b.LDAP.parse()
	}
	for _, b := range receiver {
		switch {
		case b.Reserved:
			continue
		}
		b.VI.parse()
	}
	return !status
}

func (receiver *cDB) parse() {
	var (
		v_PG_ASN = func() (outbound _Inet_ASN) {
			outbound = _Inet_ASN(parse_interface(strconv.ParseUint(re_digits.FindString(receiver.XMLName.Local), 10, 32)).(uint64))
			switch {
			case outbound == 0:
				return _S_Group
			}
			return
		}()
	)
	switch _, flag := i_peer_group[v_PG_ASN]; {
	case flag:
		log.Warnf("Peer Group '%v' already exist; ACTION: skip.", v_PG_ASN)
		return
	case receiver.Reserved:
		log.Debugf("Peer Group '%v' is reserved; ACTION: skip.", v_PG_ASN)
		i_peer_group[v_PG_ASN] = &i_Peer_Group{
			_Attribute_List: receiver._Attribute_List,
		}
		return
	}

	var (
		v_PName   = pad(v_PG_ASN, 10)
		v_ASName  = _Name(join_string("", "AS", v_PName))
		v_GT_List = func() (outbound []_Name) {
			var (
				s = make(map[_Name]bool)
			)
			for _, d := range re_string_splitters.Split(receiver.GT_List, -1) {
				switch _, flag := s[_Name(d)]; {
				case flag:
					continue
				}
				s[_Name(d)] = true
				outbound = append(outbound, _Name(d))
			}
			switch {
			case len(outbound) == 0:
				return _S_GT_List
			}
			return
		}()
		v_Domain_Name = func() (outbound _FQDN) {
			switch {
			case len(receiver.Domain_Name) == 0:
				return _S_Domain_Name
			}
			return receiver.Domain_Name
		}()
	)
	i_peer_group[v_PG_ASN] = &i_Peer_Group{
		// ASN:                 v_PG_ASN,
		// VI_RI:             _S_Master_RI,
		ASName:              v_ASName,
		Domain_Name:         v_Domain_Name,
		GT_List:             v_GT_List,
		Host_RI:             _S_Host_RI,
		Master_RI:           _S_Master_RI,
		Mgmt_IF:             _S_Mgmt_IF,
		Mgmt_RI:             _S_Mgmt_RI,
		Mgmt_RI_Description: _S_Mgmt_RI_Description,
		VI_RI:               _S_Master_RI, // _S_VI_RI,
		PName:               v_PName,
		SP_Default_Policy:   _S_SP_Default_Policy,
		VI_IP:               nil,
		UI_IP:               nil,
		Peer_List:           __ASN_Peer{},
		GT_Action:           "",
		_Attribute_List:     receiver._Attribute_List,
	}
	log.SetLevel(i_peer_group[v_PG_ASN].Verbosity)
	receiver.Peer.parse(v_PG_ASN)
	return
}

func (receiver cDB_AB_List) parse() {
	for _, b := range receiver {
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
func (receiver cDB_JA_List) parse() {
	for _, b := range receiver {
		switch _, flag := i_ja[b.Name]; {
		case flag:
			log.Debugf("Application '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ja[b.Name] = func() (outbound *i_JA) {
			outbound = &i_JA{
				Term: func() (outbound __JA_Term) {
					for _, d := range b.Term {
						outbound = append(outbound, &i_JA_Term{
							Name:             d.Name,
							Protocol:         d.Protocol,
							Destination_Port: d.Destination_Port,
							GT_Action:        join_string(" ", _W_term, d.Name, _W_protocol, d.Protocol, _W_destination__port, d.Destination_Port),
							_Attribute_List:  d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       join_string(" ", _W_applications____application, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
}
func (receiver cDB_PO_PL_List) parse() {
	for _, b := range receiver {
		switch _, flag := i_pl[b.Name]; {
		case flag:
			log.Debugf("Policy List '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_pl[b.Name] = func() (outbound *i_PO_PL) {
			outbound = &i_PO_PL{
				Match: func() (outbound __PO_PL_Match) {
					for _, d := range b.Match {
						switch {
						case !d.IPPrefix.IsValid():
							log.Warnf("Policy List '%v', invalid IP '%v'; ACTION: skip.", b.Name, d.IPPrefix.String())
						}
						outbound = append(outbound, &i_PO_PL_Match{
							IPPrefix:        d.IPPrefix,
							GT_Action:       d.IPPrefix.String(),
							_Attribute_List: d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       join_string(" ", _W_policy__options___prefix__list, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
}
func (receiver cDB_PO_PS_List) parse() {
	for _, b := range receiver {
		switch _, flag := i_ps[b.Name]; {
		case flag:
			log.Debugf("Policy Statement '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ps[b.Name] = func() (outbound *i_PO_PS) {
			outbound = &i_PO_PS{
				Term: func() (outbound __PO_PS_Term) {
					for _, d := range b.Term {
						outbound = append(outbound, &i_PO_PS_Term{
							Name: d.Name,
							From: func() (outbound __PO_PS_From) {
								for _, f := range d.From {
									outbound = append(outbound, &i_PO_PS_From{
										RI:         f.RI,
										Protocol:   f.Protocol,
										Route_Type: f.Route_Type,
										PL:         f.PL,
										Mask:       f.Mask,
										GT_Action: join_string(" ", _W_from,
											f.RI.action_RI(nil, nil, _Type_policy_statement, ""),
											f.Protocol.action(nil, nil, "", ""),
											f.Route_Type.action_Route_Type(nil, nil, "", ""),
											f.PL.action_PL(nil, nil, _Type_policy_statement, ""),
											f.Mask,
										),
										_Attribute_List: f._Attribute_List,
									})
								}
								return
							}(),
							Then: func() (outbound __PO_PS_Then) {
								for _, f := range d.Then {
									var (
										v_Action string
									)
									switch {
									case f.Metric != 0:
										v_Action = join_string(" ", _W_metric, f.Metric)
									}
									outbound = append(outbound, &i_PO_PS_Then{
										Action:          f.Action,
										Action_Flag:     f.Action_Flag,
										Metric:          f.Metric,
										GT_Action:       join_string(" ", _W_then, f.Action, f.Action_Flag, v_Action),
										_Attribute_List: f._Attribute_List,
									})
								}
								return
							}(),
							GT_Action:       join_string(" ", _W_term, d.Name),
							_Attribute_List: d._Attribute_List,
						})
					}
					return
				}(),
				GT_Action:       join_string(" ", _W_policy__options___policy__statement, b.Name),
				_Attribute_List: b._Attribute_List,
			}
			return
		}()
	}
}
func (receiver cDB_Peer_List) parse_Vocabulary() {
	for _, b := range receiver {
		switch _, flag := i_peer[b.ASN]; {
		case flag || b.Reserved:
			continue
		}
		b.AB.parse()
		b.JA.parse()
		b.PL.parse()
		b.PS.parse()
	}
}
func (receiver cDB_Peer_List) parse(v_PG_ASN _Inet_ASN) {
	for _, b := range receiver {
		switch _, flag := i_peer[b.ASN]; {
		case flag:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		case b.Reserved:
			log.Debugf("Peer '%v' is reserved; ACTION: skip.", b.ASN)
			i_peer[b.ASN] = &i_Peer{_Attribute_List: b._Attribute_List}
			continue
		}
		var (
			v_Peer = &i_Peer{
				// VI:           __VI_VI{},
				// VI_Local:     __VI_VI_Peer{},
				// VI_Remote:    __VI_VI_Peer{},
				Group:           i_peer_group[v_PG_ASN],
				ASN:             b.ASN,
				ASName:          _Name(join_string("", _Name_AS, pad_string(b.ASN, 10))),
				PName:           pad(b.ASN, 10),
				Router_ID:       netip.Addr{},
				IF_2_RI:         map[_Name]_Name{},
				VI_GT:           __VI_VI_GT{},
				IFM:             __N_Peer_IFM{},
				RI:              __N_Peer_RI{},
				Hostname:        "",
				Domain_Name:     "",
				Version:         b.Version,
				Major:           0,
				Manufacturer:    b.Manufacturer,
				Model:           b.Model,
				Serial:          b.Serial,
				Root:            b.Root.validate(16, b.ASN.String()),
				GT_List:         []_Name{},
				SZ:              __N_Peer_SZ{},
				NAT:             __T_Peer_NAT_Type{},
				AB:              __N_AB{},
				JA:              __N_JA{},
				PL:              __N_PO_PL{},
				PS:              __N_PO_PS{},
				SP:              &i_Peer_SP{Option_List: &_SP_Option_List{}},
				FW:              nil,
				IKE_GCM:         false,
				GT_Action:       "",
				_Attribute_List: b._Attribute_List,
			}
		)
		v_Peer.create_AB_Set(_Name(join_string("_", "O", v_Peer.ASName)), _Name(join_string("_", "I", v_Peer.ASName)))
		b.parse_Version(v_Peer)
		v_Peer.IKE_GCM = v_Peer.Major >= 12.3
		b.parse_RI(v_Peer)

		// Group
		// ASN
		// ASName
		// PName
		b.parse_Router_ID(v_Peer)
		// IF_2_RI
		// VI
		// VI_Local
		// VI_Remote
		// VI_GT
		b.parse_IFM(v_Peer)
		// RI
		b.parse_Hostname(v_Peer)
		b.parse_Domain_Name(v_Peer)
		// Version
		// Major
		// Manufacturer
		// Model
		// SN
		// Root
		b.parse_GT_List(v_Peer)
		b.parse_SZ(v_Peer)
		b.parse_NAT(v_Peer)
		// AB
		// JA
		// PL
		// PS
		b.parse_SP(v_Peer)
		b.parse_FW(v_Peer)
		// IKE_GCM

		i_peer[b.ASN] = v_Peer
		i_peer_group[v_PG_ASN].Peer_List[b.ASN] = i_peer[b.ASN]
		i_peer_list = append(i_peer_list, b.ASN)
	}
}
func (receiver cDB_VI_List) parse() {
	for _, b := range receiver {
		switch _, flag := i_vi[b.ID]; {
		case flag:
			log.Warnf("VI '%v' already exist; ACTION: skip.", b.ID)
			continue
		case b.Reserved:
			log.Debugf("VI '%v' is reserved; ACTION: skip.", b.ID)
			i_vi[b.ID] = &i_VI{}
			continue
		}
		var (
			v_vi_peer_list = make(__VIC_VI_Peer)
		)
		i_vi[b.ID] = &i_VI{
			PName: pad(&b.ID, 5),
			// IPPrefix:      get_VI_IPPrefix(nil, b.ID, 0).Masked(),
			Type:          _Type_st,
			Communication: b.Communication.parse(_S_Comm[_comm_vi]),
			Route_Metric: func() _INet_Routing {
				switch {
				case b.Route_Metric > _Route_Weight_max_rm:
					return 0
				}
				return _Route_Weight_max_rm - b.Route_Metric
			}(),
			PSK:             b.PSK.validate(64, b.ID.String()),
			Hub:             false,
			IKE_GCM:         true,
			IKE_No_NAT:      true,
			GT_Action:       "",
			_Attribute_List: b._Attribute_List,
		}
		i_vi_peer[b.ID] = __VIC_VI_Peer{}

		for _, d := range b.Peer {
			switch _, flag := i_peer[d.ASN]; {
			case !flag:
				log.Warnf("VI '%v', Peer '%v' not found; ACTION: skip.", b.ID, d.ID)
				continue
			}
			switch _, flag := i_vi_peer[b.ID][d.ID]; {
			case d.ID > 1:
				log.Warnf("VI '%v', Peer '%v', index out of range; ACTION: skip.", b.ID, d.ID)
				continue
			case flag:
				log.Warnf("VI '%v', Peer '%v' already exist; ACTION: skip.", b.ID, d.ID)
				continue
			case d.Reserved:
				log.Debugf("VI '%v', Peer '%v' is reserved; ACTION: skip.", b.ID, d.ID)
				continue
			}

			// todo: WTF ....
			i_vi[b.ID].IPPrefix = i_vi_ip[b.ID].IPPrefix

			var (
				v_RI                = d.RI.validate_RI(i_peer[d.ASN], "", i_peer[d.ASN].Group.Mgmt_RI)
				v_IF                = d.IF
				v_IP                = d.IP
				v_NAT               netip.Prefix
				v_IKE_Local_Address bool
				v_IKE_Dynamic       bool
			)

			switch _, flag := i_peer[d.ASN].RI[v_RI]; {
			case !flag:
				log.Warnf("VI '%v', Peer '%v', ASN '%v', RI '%v' not found; ACTION: skip.", b.ID, d.ID, d.ASN, v_RI)
				continue
			}

			switch _, flag := i_peer[d.ASN].RI[v_RI].IF[v_IF]; {
			case !flag:
				for v_IF = range i_peer[d.ASN].RI[v_RI].IF {
					break
				}
			}

			switch _, flag := i_peer[d.ASN].RI[v_RI].IF[v_IF]; {
			case !flag:
				log.Warnf("VI '%v', Peer '%v', ASN '%v', RI '%v', IF'%v' not found; ACTION: skip.", b.ID, d.ID, d.ASN, v_RI, v_IF)
				continue
			}
			switch _, flag := i_peer[d.ASN].RI[v_RI].IP_IF[v_IP]; {
			case v_IP.IsValid() && !flag: // IP defined but not found
				log.Warnf("VI '%v', Peer '%v', ASN '%v', RI '%v', IF '%v', IP '%v' not found; ACTION: skip.", b.ID, d.ID, d.ASN, v_RI, v_IF, v_IP)
				continue
			case !flag: // IP not defined and not found
				for v_IP = range i_peer[d.ASN].RI[v_RI].IF[v_IF].IP {
					switch {
					case v_IP.IsValid():
						break
					}
				}
			}
			v_NAT = v_IP
			for e, f := range i_peer[d.ASN].RI[v_RI].IF[v_IF].IP {
				switch {
				case e.Addr() == v_IP.Addr() && f.NAT.IsValid():
					v_NAT = f.NAT
				}
			}
			v_IKE_Dynamic = !v_NAT.IsValid() || v_NAT.Addr().IsPrivate()
			v_IKE_Local_Address = len(i_peer[d.ASN].RI[v_RI].IF[v_IF].IP) > 1

			i_vi_peer[b.ID][d.ID] = &i_VI_Peer{
				ASN:               d.ASN,
				RI:                v_RI,
				IF:                v_IF,
				IPPrefix:          v_IP,
				NAT:               v_NAT,
				Hub:               d.Hub,
				Inner_RI:          d.Inner_RI.validate_RI(i_peer[d.ASN], i_peer[d.ASN].Group.VI_RI, i_peer[d.ASN].Group.Mgmt_RI),
				Inner_IPPrefix:    i_vi_ip[b.ID].Conn[d.ID+1],
				IKE_Local_Address: v_IKE_Local_Address,
				IKE_Dynamic:       v_IKE_Dynamic,
				GT_Action:         "",
				_Attribute_List:   d._Attribute_List,
			}
			v_vi_peer_list[d.ID] = i_vi_peer[b.ID][d.ID]
		}

		var (
			_first, _second _VI_Conn_ID
			_total          = _VI_Conn_ID(len(v_vi_peer_list))
			_if             = _Name(join_string(".", c_VI_Action[i_vi[b.ID].Type], b.ID))
		)
		switch {
		case _total != 2:
			continue
		}

		for _first, _second = 0, _total-1; _first <= _total-1; _first, _second = _first+1, _second-1 {

			i_vi[b.ID].IKE_GCM = i_vi[b.ID].IKE_GCM && i_peer[v_vi_peer_list[_first].ASN].IKE_GCM

			// i_peer[v_vi_peer_list[_first].ASN].VI[b.ID] = i_vi[b.ID]
			// i_peer[v_vi_peer_list[_first].ASN].VI_Local[b.ID] = i_vi_peer[b.ID][_first]
			// i_peer[v_vi_peer_list[_first].ASN].VI_Remote[b.ID] = i_vi_peer[b.ID][_second]

			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = &i_Peer_RI_IF{
				IFM:           _Name(c_VI_Action[i_vi[b.ID].Type]),
				IFsM:          _Name(b.ID.String()),
				Communication: _S_Comm[_comm_vi],
				IP: __IPP_Peer_RI_IF_IP{
					i_vi_peer[b.ID][_first].Inner_IPPrefix: {
						Masked:          i_vi_peer[b.ID][_first].Inner_IPPrefix.Masked(),
						Primary:         false,
						Preferred:       false,
						NAT:             netip.Prefix{},
						DHCP:            false,
						GT_Action:       "",
						_Attribute_List: _Attribute_List{},
					},
				},
				PARP:            nil,
				GT_Action:       "",
				_Attribute_List: _Attribute_List{Description: _Description(join_string("_", i_vi_peer[b.ID][_first].IF, i_peer[v_vi_peer_list[_second].ASN].ASName, i_vi_peer[b.ID][_second].IF))},
			}
			i_peer[v_vi_peer_list[_first].ASN].SZ[i_vi_peer[b.ID][_first].Inner_RI].IF[_if] = &i_Peer_SZ_IF{
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh, _Protocol_bgp),
				GT_Action:                  join_string(" ", _W_interfaces, _if),
				_Attribute_List:            _Attribute_List{},
			}
			i_peer[v_vi_peer_list[_first].ASN].IF_2_RI[_if] = i_vi_peer[b.ID][_first].Inner_RI
			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].IP_IF[i_vi_peer[b.ID][_first].Inner_IPPrefix] = _if
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
				Local_IP:                 i_vi_peer[b.ID][_first].IPPrefix.Addr(),
				Local_NAT:                i_vi_peer[b.ID][_first].NAT.Addr(),
				Local_Hub:                i_vi_peer[b.ID][_first].Hub,
				Local_Inner_RI:           i_vi_peer[b.ID][_first].Inner_RI,
				Local_Inner_IP:           i_vi_peer[b.ID][_first].Inner_IPPrefix.Addr(),
				Local_Inner_IPPrefix:     i_vi_peer[b.ID][_first].Inner_IPPrefix,
				Local_IKE_Local_Address:  i_vi_peer[b.ID][_first].IKE_Local_Address,
				Local_IKE_Dynamic:        i_vi_peer[b.ID][_first].IKE_Dynamic,
				Remote_ASN:               i_vi_peer[b.ID][_second].ASN,
				Remote_RI:                i_vi_peer[b.ID][_second].RI,
				Remote_IF:                i_vi_peer[b.ID][_second].IF,
				Remote_IP:                i_vi_peer[b.ID][_second].IPPrefix.Addr(),
				Remote_NAT:               i_vi_peer[b.ID][_second].NAT.Addr(),
				Remote_Hub:               i_vi_peer[b.ID][_second].Hub,
				Remote_Inner_RI:          i_vi_peer[b.ID][_second].Inner_RI,
				Remote_Inner_IP:          i_vi_peer[b.ID][_second].Inner_IPPrefix.Addr(),
				Remote_Inner_IPPrefix:    i_vi_peer[b.ID][_second].Inner_IPPrefix,
				Remote_IKE_Local_Address: i_vi_peer[b.ID][_second].IKE_Local_Address,
				Remote_IKE_Dynamic:       i_vi_peer[b.ID][_second].IKE_Dynamic,
				GT_Action:                "",
				_Attribute_List:          _Attribute_List{},
			}
			switch _, flag := i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[i_peer[v_vi_peer_list[_first].ASN].Group.ASName]; {
			case !flag:
				i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[i_peer[v_vi_peer_list[_first].ASN].Group.ASName] = &_BGP_Group{
					Local_ASN:  0,
					Remote_ASN: 0,
					Passive:    false,
					Neighbor:   __A_BGP_Group_Neighbor{},
					GT_Action:  join_string(" ", _W_group, i_peer[v_vi_peer_list[_first].ASN].Group.ASName),
				}
			}
			i_peer[v_vi_peer_list[_first].ASN].RI[i_vi_peer[b.ID][_first].Inner_RI].BGP.BGP_Group[i_peer[v_vi_peer_list[_first].ASN].Group.ASName].Neighbor[i_vi_peer[b.ID][_second].Inner_IPPrefix.Addr()] = &_BGP_Group_Neighbor{
				Local_ASN:  i_vi_peer[b.ID][_first].ASN,
				Remote_ASN: i_vi_peer[b.ID][_second].ASN,
				Passive:    i_vi_peer[b.ID][_first].Hub,
				Local_IP:   i_vi_peer[b.ID][_first].Inner_IPPrefix.Addr(),
				Route_Leak: parse_iDB_Route_Leak(nil, i_peer[v_vi_peer_list[_first].ASN], "", "", __W_Route_Leak_FromTo{
					_W_import: {PS: []_Name{0: _Name(join_string("_", _W_import_metric, pad_string(i_vi[b.ID].Route_Metric, 2)))}},
					_W_export: {PS: []_Name{0: _Name(_W_aggregate), 1: _Name(join_string("_", _W_export_metric, pad_string(i_vi[b.ID].Route_Metric, 2)))}},
				}),
				GT_Action:       join_string(" ", _W_neighbor, i_vi_peer[b.ID][_second].Inner_IPPrefix.Addr()),
				_Attribute_List: _Attribute_List{Description: _Description(join_string("", "TI", i_vi[b.ID].PName))},
			}
		}
	}
}
func (receiver cDB_LDAP_List) parse() {
	for _, b := range receiver { // parse server params
		var (
			c = parse_interface(url.Parse(b.URL)).(*url.URL)
			d = &url.URL{
				Scheme:      c.Scheme,
				Opaque:      "",
				User:        nil,
				Host:        c.Host,
				Path:        "",
				RawPath:     "",
				ForceQuery:  false,
				RawQuery:    "",
				Fragment:    "",
				RawFragment: "",
			}
		)
		switch _, flag := i_ldap[d]; {
		case flag:
			log.Warnf("LDAP '%v' already defined; ACTION: skip.", d)
			continue
		case b.Reserved:
			log.Debugf("LDAP '%v' is reserved; ACTION: skip.", d)
			continue
		case len(c.Path) == 0:
			c.Path = _S_cn_config
		}
		switch {
		case len(b.DB_Filter) == 0:
			b.DB_Filter = _S_filter_db
		}
		switch {
		case len(b.DB_CN) == 0:
			b.DB_CN = _S_cn_db
		}
		switch {
		case len(b.DC_Filter) == 0:
			b.DC_Filter = _S_filter_dc
		}
		switch {
		case len(b.DC_CN) == 0:
			b.DC_CN = _S_cn_dc
		}
		switch {
		case len(b.Host_Filter) == 0:
			b.Host_Filter = _S_filter_host
		}
		switch {
		case len(b.Host_CN) == 0:
			b.Host_CN = _S_cn_host
		}
		switch {
		case len(b.Group_Filter) == 0:
			b.Group_Filter = _S_filter_group
		}
		switch {
		case len(b.Group_CN) == 0:
			b.Group_CN = _S_cn_group
		}
		switch {
		case len(b.User_Filter) == 0:
			b.User_Filter = _S_filter_user
		}
		switch {
		case len(b.User_CN) == 0:
			b.User_CN = _S_cn_user
		}
		switch {
		case len(b.CA_Filter) == 0:
			b.CA_Filter = _S_filter_ca
		}
		switch {
		case len(b.CA_CN) == 0:
			b.CA_CN = _S_cn_ca
		}
		i_ldap[d] = &i_LDAP{
			Bind_DN:      b.Bind_DN,
			DB_CN:        b.DB_CN,
			DB_Filter:    b.DB_Filter,
			DC_CN:        b.DC_CN,
			DC_Filter:    b.DC_Filter,
			Domain:       __DN_LDAP_Domain{},
			Group_CN:     b.Group_CN,
			Group_Filter: b.Group_Filter,
			Host_CN:      b.Host_CN,
			Host_Filter:  b.Host_Filter,
			Admin_DN:     split_2_strings(b.Admin_DN, re_strict_splitters),
			CA_Filer:     b.CA_Filter,
			CA_CN:        b.CA_CN,
			M_CN_G:       __DN_LDAP_Domain_Group{},
			M_CN_U:       __DN_LDAP_Domain_User{},
			Modify:       nil,
			PKI:          nil,
			Secret:       b.Secret,
			URL:          c,
			User_CN:      b.User_CN,
			User_Filter:  b.User_Filter,
		}
	}
}

func (receiver *cDB_Peer) parse_Router_ID(v_Peer *i_Peer) {
	switch {
	case receiver.Router_ID.IsValid():
		v_Peer.Router_ID = receiver.Router_ID
	default:
		v_Peer.Router_ID = func() netip.Addr {
			for a := range v_Peer.RI[v_Peer.Group.Master_RI].IF[_Name_lo0_0].IP {
				switch {
				case a.IsValid():
					return a.Addr()
				}
			}
			return parse_interface(netip.ParseAddr("192.0.2.0")).(netip.Addr)
		}()
		log.Debugf("Peer '%v', invalid Router_ID '%v'; ACTION: use '%v'.", receiver.ASN, receiver.Router_ID, v_Peer.Router_ID)
	}
}
func (receiver *cDB_Peer) parse_IFM(v_Peer *i_Peer) {
	for _, b := range receiver.IFM {
		v_Peer.IFM[b.Name] = &i_Peer_IFM{
			Communication:   b.Communication.parse(_S_Comm[_comm_if]),
			GT_Action:       join_string(" ", _W_interfaces, b.Name),
			_Attribute_List: b._Attribute_List,
		}
	}
}
func (receiver *cDB_Peer) parse_RI(v_Peer *i_Peer) {
	for _, b := range receiver.RI {
		switch _, flag := v_Peer.RI[b.Name]; {
		case flag:
			log.Warnf("Peer '%v', RI '%v' already exist; ACTION: ignore.", receiver.ASN, b.Name)
			continue
		}
		cDB_PO_PS_List{
			0: {Name: _Name(join_string("_", _W_redistribute, b.Name)),
				Term: cDB_PO_PS_Term_List{
					// 0: {Name: empty_Name.next_ID(),
					0: {Name: "PERMIT",
						From:            cDB_PO_PS_From_List{0: {RI: b.Name, _Attribute_List: _Attribute_List{}}},
						Then:            cDB_PO_PS_Then_List{0: {Action: _W_accept, _Attribute_List: _Attribute_List{}}},
						_Attribute_List: _Attribute_List{},
					},
				},
				_Attribute_List: _Attribute_List{},
			},
		}.parse()
		v_Peer.link_PS(_Name(join_string("_", _W_redistribute, b.Name)))
	}
	for _, b := range receiver.RI {
		switch _, flag := v_Peer.RI[b.Name]; {
		case flag:
			log.Warnf("Peer '%v', RI '%v' already exist; ACTION: ignore.", receiver.ASN, b.Name)
			continue
		}
		var (
			v_IP_IF = make(map[netip.Prefix]_Name)
			v_IF    = func() (outbound __N_Peer_RI_IF) {
				outbound = make(__N_Peer_RI_IF)
				for _, d := range b.IF {
					switch value, flag := v_Peer.IF_2_RI[d.Name]; {
					case flag:
						log.Warnf("Peer '%v', RI '%v', IF '%v' already exist in RI '%v'; ACTION: ignore.", receiver.ASN, b.Name, d.Name, value)
						continue
					}
					v_Peer.IF_2_RI[d.Name] = b.Name
					var (
						v_IF_IFM  string
						v_IF_IFsM string
					)
					get_string(&d.Name, re_dots, &v_IF_IFM, &v_IF_IFsM)
					outbound[d.Name] = &i_Peer_RI_IF{
						IFM:           _Name(v_IF_IFM),
						IFsM:          _Name(v_IF_IFsM),
						Communication: d.Communication.parse(_S_Comm[_comm_if]),
						IP: func() (outbound __IPP_Peer_RI_IF_IP) {
							outbound = make(__IPP_Peer_RI_IF_IP)
							for _, f := range d.IP {
								switch {
								case !f.DHCP:
									switch value, flag := v_IP_IF[f.IPPrefix]; {
									case flag:
										log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' with IF '%v'; ACTION: ignore.", receiver.ASN, b.Name, d.Name, f.IPPrefix, value)
										continue
									case !f.IPPrefix.IsValid():
										log.Warnf("Peer '%v', RI '%v', IF '%v', invalid IP '%v'; ACTION: ignore.", receiver.ASN, b.Name, d.Name, f.IPPrefix)
										continue
									}
									v_IP_IF[f.IPPrefix] = d.Name
								}
								add_iDB_AB_Address_List(true, false, _Name_PUBLIC, f.IPPrefix.Addr(), f.NAT)
								add_iDB_AB_Address_List(true, false, _Name(join_string("_", "O", v_Peer.ASName)), f.IPPrefix, f.NAT)
								add_iDB_AB_Address_List(false, true, _Name(join_string("_", "I", v_Peer.ASName)), f.IPPrefix, f.NAT)
								outbound[f.IPPrefix] = &i_Peer_RI_IF_IP{
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
						PARP: func() (outbound __IPP_Peer_RI_IF_PARP) {
							outbound = make(__IPP_Peer_RI_IF_PARP)
							for _, f := range d.PARP {
								switch {
								case !f.IP.IsValid():
									log.Warnf("Peer '%v', RI '%v', IF '%v', invalid PARP IP '%v'; ACTION: ignore.", receiver.ASN, b.Name, d.Name, f.IP)
									continue
								}
								switch value, flag := v_IP_IF[f.IP]; {
								case flag:
									log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' on IF '%v'; ACTION: ignore.", receiver.ASN, b.Name, d.Name, f.IP, value)
									continue
								}
								v_IP_IF[f.IP] = d.Name
								add_iDB_AB_Address_List(true, false, _Name_PUBLIC, f.IP, f.NAT)
								outbound[f.IP] = &i_Peer_RI_IF_PARP{
									NAT:             f.NAT,
									GT_Action:       join_string(" ", _W_security___nat___proxy__arp),
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
			v_RT = func() (outbound __IPP_Peer_RI_RO_RT) {
				outbound = make(__IPP_Peer_RI_RO_RT)
				for _, d := range b.RT {
					switch {
					case !d.Identifier.IsValid():
						log.Warnf("Peer '%v', RI '%v', route Identifier '%v' is invalid; ACTION: ignore.", receiver.ASN, b.Name, d.Identifier)
						continue
					}
					outbound[d.Identifier] = &i_Peer_RI_RO_RT{
						GW: func() (outbound __N_Peer_RI_RO_RT_GW) {
							outbound = make(__N_Peer_RI_RO_RT_GW)
							for _, f := range d.GW {
								var (
									v_RT_IP          netip.Addr
									v_RT_IF          _Name
									v_RT_Table       _Name
									v_RT_Action      = f.Action.validate_RO_GW_Action(nil, v_Peer)
									v_RT_Action_Flag _W
									v_Action         = join_string(" ", _W_static___route, d.Identifier)
								)
								switch {
								case v_RT_Action == _W_discard:
									v_Action = join_string(" ", v_Action, v_RT_Action)
								case v_RT_Action == _W_next__table && len(f.Table) != 0:
									v_RT_Table = f.Table
									v_Action = join_string(" ", v_Action, v_RT_Action, v_RT_Table)
								case (v_RT_Action == _W_next__hop || v_RT_Action == _W_qualified__next__hop) && len(f.IF) != 0:
									v_RT_IF = f.IF
									v_Action = join_string(" ", v_Action, v_RT_Action, v_RT_IF)
								case (v_RT_Action == _W_next__hop || v_RT_Action == _W_qualified__next__hop) && f.IP.IsValid():
									v_RT_IP = f.IP
									v_Action = join_string(" ", v_Action, v_RT_Action, v_RT_IP)
								case len(v_RT_Action) == 0 && len(f.Table) != 0:
									v_RT_Action = _W_next__table
									v_RT_Table = f.Table
									v_Action = join_string(" ", v_Action, v_RT_Action, v_RT_Table)
								case len(v_RT_Action) == 0 && len(f.IF) != 0:
									v_RT_Action = _W_next__hop
									v_RT_IF = f.IF
									v_Action = join_string(" ", v_Action, v_RT_Action, v_RT_IF)
								case len(v_RT_Action) == 0 && f.IP.IsValid():
									v_RT_Action = _W_next__hop
									v_RT_IP = f.IP
									v_Action = join_string(" ", v_Action, v_RT_Action, v_RT_IP)
								case len(v_RT_Action) == 0:
									v_RT_Action = _W_discard
									v_Action = join_string(" ", v_Action, v_RT_Action)
								default:
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', invalid GW '%v'; ACTION: ignore.", receiver.ASN, b.Name, d.Identifier, f)
									continue
								}
								switch {
								case f.Metric > 0:
									v_Action = join_string(" ", v_Action, _W_metric, f.Metric)
								}
								switch {
								case f.Preference > 0:
									v_Action = join_string(" ", v_Action, _W_preference, f.Preference)
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
									log.Warnf("Peer '%v', RI '%v', Identifier '%v', GW '%v' already exist; ACTION: ignore.", receiver.ASN, b.Name, d.Identifier, f)
									continue
								}
								outbound[v_Name] = &v_GW
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
				case b.Name != v_Peer.Group.Master_RI:
					return join_string(" ", _W_routing__instances, b.Name)
				}
				return ""
			}()
		)

		v_Peer.RI[b.Name] = &i_Peer_RI{
			IP_IF:           v_IP_IF,
			IF:              v_IF,
			RT:              v_RT,
			Route_Leak:      receiver.parse_Route_Leak(v_Peer, "", "", &b.Route_Leak),
			Protocol:        nil,
			BGP:             _BGP{BGP_Group: __N_BGP_Group{}, GT_Action: join_string(" ", _W_protocols___bgp), _Attribute_List: _Attribute_List{}},
			GT_Action:       v_Action,
			_Attribute_List: b._Attribute_List,
		}
	}
}
func (receiver *cDB_Peer) parse_Hostname(v_Peer *i_Peer) {
	switch {
	case len(receiver.Hostname) == 0:
		v_Peer.Hostname = _FQDN(join_string("", "gw_as", pad_string(receiver.ASN, 10)))
		log.Warnf("Peer '%v', Hostname '%v' is invalid; ACTION: use '%v'.", receiver.ASN, receiver.Router_ID, v_Peer.Hostname)
	default:
		v_Peer.Hostname = receiver.Hostname
	}
}
func (receiver *cDB_Peer) parse_Domain_Name(v_Peer *i_Peer) {
	switch {
	case len(receiver.Domain_Name) == 0:
		v_Peer.Domain_Name = v_Peer.Group.Domain_Name
	default:
		v_Peer.Domain_Name = receiver.Domain_Name
	}
}
func (receiver *cDB_Peer) parse_Version(v_Peer *i_Peer) {
	// var (
	// 	v_Major string
	// )
	// get_string(&receiver.Version, re_upper_case, &v_Major)
	// v_Peer.Major = parse_interface(strconv.ParseFloat(v_Major, 64)).(float64)

	var (
		v_Version = re_upper_case.Split(receiver.Version, -1)
	)
	v_Peer.Major = parse_interface(strconv.ParseFloat(v_Version[0], 64)).(float64)
}

func (receiver *cDB_Peer) parse_GT_List(v_Peer *i_Peer) {
	switch {
	case len(receiver.GT_List) != 0:
		for _, b := range receiver.GT_List {
			v_Peer.GT_List = append(v_Peer.GT_List, _Name(b))
		}
	default:
		v_Peer.GT_List = v_Peer.Group.GT_List
		v_Peer.GT_List = append(v_Peer.GT_List, v_Peer.ASName)
	}
}
func (receiver *cDB_Peer) parse_SZ(v_Peer *i_Peer) {
	for _, b := range receiver.SZ {
		switch {
		case b.Name == v_Peer.Group.Mgmt_RI:
			log.Warnf("Peer '%v', SZ '%v' cannot be defined; ACTION: ignore.", receiver.ASN, b.Name)
			continue
		}
		v_Peer.SZ[b.Name] = &i_Peer_SZ{
			Screen: b.Screen,
			IF: func() (outbound __N_Peer_SZ_IF) {
				outbound = make(__N_Peer_SZ_IF)
				for c := range v_Peer.RI[b.Name].IF {
					outbound[c] = &i_Peer_SZ_IF{
						_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
						GT_Action:                  join_string(" ", _W_interfaces, c),
						_Attribute_List:            _Attribute_List{},
					}
				}
				return
			}(),
			_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
			GT_Action:                  join_string(" ", _W_security__zones___security__zone, b.Name),
			_Attribute_List:            b._Attribute_List,
		}
	}
	for a := range v_Peer.RI {
		switch a {
		case v_Peer.Group.Mgmt_RI:
			continue
		}
		switch _, flag := v_Peer.SZ[a]; {
		case !flag:
			v_Peer.SZ[a] = &i_Peer_SZ{
				Screen:                     "",
				IF:                         __N_Peer_SZ_IF{},
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(),
				GT_Action:                  join_string(" ", _W_security__zones___security__zone, a),
				_Attribute_List:            _Attribute_List{},
			}
		}
		for e := range v_Peer.RI[a].IF {
			switch _, flag := v_Peer.SZ[a].IF[e]; {
			case flag:
				continue
			}
			v_Peer.SZ[a].IF[e] = &i_Peer_SZ_IF{
				_Host_Inbound_Traffic_List: parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh),
				GT_Action:                  join_string(" ", _W_interfaces, e),
				_Attribute_List:            _Attribute_List{},
			}
		}
	}
}
func (receiver *cDB_Peer) parse_NAT(v_Peer *i_Peer) {
	var (
		h = receiver.NAT_Source
	)
	v_Peer.NAT[_Type_source] = &i_Peer_NAT_Type{
		Address_Persistent: h.Address_Persistent,
		Pool:               receiver.parse_Pool(v_Peer, _Type_source, _Type_pool, h.Pool),
		Rule_Set:           receiver.parse_Rule_Set(v_Peer, _Type_source, "", h.Rule_Set),
		GT_Action:          join_string(" ", _W_security___nat___source),
		_Attribute_List:    h._Attribute_List,
	}

	h = receiver.NAT_Destination

	v_Peer.NAT[_Type_destination] = &i_Peer_NAT_Type{
		Pool:            receiver.parse_Pool(v_Peer, _Type_destination, _Type_pool, h.Pool),
		Rule_Set:        receiver.parse_Rule_Set(v_Peer, _Type_destination, "", h.Rule_Set),
		GT_Action:       join_string(" ", _W_security___nat___destination),
		_Attribute_List: h._Attribute_List,
	}

	h = receiver.NAT_Static

	v_Peer.NAT[_Type_static] = &i_Peer_NAT_Type{
		Pool:            receiver.parse_Pool(v_Peer, _Type_static, _Type_pool, h.Pool),
		Rule_Set:        receiver.parse_Rule_Set(v_Peer, _Type_static, "", h.Rule_Set),
		GT_Action:       join_string(" ", _W_security___nat___static),
		_Attribute_List: h._Attribute_List,
	}
}
func (receiver *cDB_Peer) parse_SP(v_Peer *i_Peer) {
	v_Peer.SP.Option_List = &_SP_Option_List{
		Default_Policy: func() _W {
			switch value := receiver.SP_Option_List.Default_Policy; value {
			case _W_permit__all, _W_deny__all:
				return value
			case "":
				return v_Peer.Group.SP_Default_Policy
			default:
				log.Warnf("Peer '%v', unknown default security policy '%v'; ACTION: use '%v'.", receiver.ASN, value, v_Peer.Group.SP_Default_Policy)
				return v_Peer.Group.SP_Default_Policy
			}
		}(),
		GT_Action: "",
	}
	for _, j := range receiver.SP_Exact {
		for _, l := range j.To {
			for _, n := range j.From {
				v_Peer.SP.Exact = append(v_Peer.SP.Exact, &i_Rule_Set{
					From:            receiver.parse_FromTo(v_Peer, _Type_exact, _Type_from, cDB_FromTo_List{0: n}),
					To:              receiver.parse_FromTo(v_Peer, _Type_exact, _Type_to, cDB_FromTo_List{0: l}),
					Rule:            receiver.parse_Rule(v_Peer, _Type_exact, "", j.Rule),
					GT_Action:       "",
					_Attribute_List: j._Attribute_List,
				})
				var (
					t = v_Peer.SP.Exact[len(v_Peer.SP.Exact)-1]
				)
				switch {
				case len(t.From) != 1 || len(t.To) != 1:
					continue
				}
				t.GT_Action = join_string(" ", _W_security___policies, _W_from__zone, t.From[0].SZ, _W_to__zone, t.To[0].SZ)
			}
		}
	}
	for _, j := range receiver.SP_Global {
		v_Peer.SP.Global = append(v_Peer.SP.Global, &i_Rule{
			Name:            j.Name,
			JA:              receiver.parse_Match_2_Name(v_Peer, j.Match),
			From:            receiver.parse_FromTo(v_Peer, _Type_global, _Type_from, j.From),
			To:              receiver.parse_FromTo(v_Peer, _Type_global, _Type_to, j.To),
			Then:            receiver.parse_Then(v_Peer, _Type_global, _Type_then, j.Then),
			GT_Action:       join_string(" ", _W_security___policies___global___policy, j.Name),
			_Attribute_List: j._Attribute_List,
		})
	}
}
func (receiver *cDB_Peer) parse_FW(v_Peer *i_Peer) {
	for _, b := range receiver.FW {
		v_Peer.FW = append(v_Peer.FW, &i_FW{
			Name: b.Name,
			Term: func() (outbound __FW_Term) {
				for _, d := range b.Term {
					outbound = append(outbound, &i_FW_Term{
						Name: d.Name,
						From: func() (outbound __FW_FromTo) {
							for _, f := range d.From {
								outbound = append(outbound, &i_FW_FromTo{
									PL:              f.PL,
									GT_Action:       f.PL.action_PL(receiver, v_Peer, _Type_firewall, _Type_from),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						To: func() (outbound __FW_FromTo) {
							for _, f := range d.To {
								outbound = append(outbound, &i_FW_FromTo{
									PL:              f.PL,
									GT_Action:       f.PL.action_PL(receiver, v_Peer, _Type_firewall, _Type_to),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						Then: func() (outbound __FW_Then) {
							for _, f := range d.Then {
								outbound = append(outbound, &i_FW_Then{
									Action:          f.Action,
									Action_Flag:     f.Action_Flag,
									RI:              f.RI,
									GT_Action:       join_string(" ", _W_then, f.Action, f.Action_Flag, f.RI.action_RI(receiver, v_Peer, _Type_firewall, _Type_then)),
									_Attribute_List: f._Attribute_List,
								})
							}
							return
						}(),
						GT_Action:       join_string(" ", _W_term, d.Name),
						_Attribute_List: d._Attribute_List,
					})
				}
				return
			}(),
			GT_Action:       join_string(" ", _W_firewall___filter, b.Name),
			_Attribute_List: b._Attribute_List,
		})
	}
}

func (receiver *cDB_Peer) parse_Pool(v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound cDB_Pool_List) (outbound __N_Pool) {
	outbound = make(__N_Pool)
	for _, j := range inbound {
		switch {
		case !j.IPPrefix.IsValid():
			log.Warnf("Peer '%v', Pool '%v', invalid IP '%v'; ACTION: skip.", receiver.ASN, j.Name, j.IPPrefix)
			continue
		}
		outbound[j.Name] = &i_Pool{
			IPPrefix:  j.IPPrefix,
			RI:        j.RI,
			SZ:        j.SZ,
			Port:      j.Port,
			Port_Low:  j.Port_Low,
			Port_High: j.Port_High,
			GT_Action: join_string(" ",
				j.RI.action_RI(receiver, v_Peer, inbound_type, inbound_direction),
				j.SZ.action_SZ(receiver, v_Peer, inbound_type, inbound_direction),
				action_Port(receiver, v_Peer, inbound_type, inbound_direction, j.Port, j.Port_Low, j.Port_High),
			),
			_Attribute_List: j._Attribute_List,
		}
	}
	return
}
func (receiver *cDB_Peer) parse_Rule_Set(v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound cDB_Rule_Set_List) (outbound __N_Rule_Set) {
	outbound = make(__N_Rule_Set)
	for _, j := range inbound {
		outbound[j.Name] = &i_Rule_Set{
			Name:            j.Name,
			From:            receiver.parse_FromTo(v_Peer, inbound_type, _Type_from, j.From),
			To:              receiver.parse_FromTo(v_Peer, inbound_type, _Type_to, j.To),
			Rule:            receiver.parse_Rule(v_Peer, inbound_type, inbound_direction, j.Rule),
			GT_Action:       join_string(" ", _W_rule__set, j.Name),
			_Attribute_List: j._Attribute_List,
		}
	}
	return
}
func (receiver *cDB_Peer) parse_Rule(v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound cDB_Rule_List) (outbound __Rule) {
	for _, j := range inbound {
		outbound = append(outbound, &i_Rule{
			Name:            j.Name,
			JA:              receiver.parse_Match_2_Name(v_Peer, j.Match),
			From:            receiver.parse_FromTo(v_Peer, inbound_type, _Type_from, j.From),
			To:              receiver.parse_FromTo(v_Peer, inbound_type, _Type_to, j.To),
			Then:            receiver.parse_Then(v_Peer, inbound_type, _Type_then, j.Then),
			GT_Action:       j.Name.String(),
			_Attribute_List: j._Attribute_List,
		})
	}
	return
}
func (receiver *cDB_Peer) parse_Match_2_Name(v_Peer *i_Peer, inbound cDB_Match_List) (outbound []_Name) {
	for _, j := range inbound {
		switch _, flag := i_ja[j.Application]; {
		// todo
		case parse_interface(regexp.MatchString("^(junos-|any$)", string(j.Application))).(bool):
		case len(j.Application) != 0 && !flag:
			log.Warnf("Peer '%v', unknown Application '%v'; ACTION: skip.", receiver.ASN, j.Application)
			continue
		}
		outbound = append(outbound, j.Application)
		v_Peer.link_JA(j.Application)
	}
	return
}
func (receiver *cDB_Peer) parse_Then(v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound cDB_Then_List) (outbound __Then) {
	for _, j := range inbound {
		outbound = append(outbound, &i_Then{
			Action:      j.Action,
			Action_Flag: j.Action_Flag,
			Pool:        j.Pool,
			AB:          j.AB,
			RI:          j.RI,
			Port_Low:    j.Port_Low,
			Port_High:   j.Port_High,
			GT_Action: join_string(" ", j.Action, j.Action_Flag,
				j.AB.action_AB(receiver, v_Peer, inbound_type, inbound_direction),
				j.RI.action_RI(receiver, v_Peer, inbound_type, inbound_direction),
				j.Pool.action_Pool(receiver, v_Peer, inbound_type, inbound_direction),
				action_Port(receiver, v_Peer, inbound_type, inbound_direction, 0, j.Port_Low, j.Port_High),
			),
			_Attribute_List: j._Attribute_List,
		})
	}
	return
}
func (receiver *cDB_Peer) parse_FromTo(v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, inbound cDB_FromTo_List) (outbound __FromTo) {
	for _, j := range inbound {
		outbound = append(outbound, &i_FromTo{
			AB:        j.AB,
			IF:        j.IF,
			RG:        j.RG,
			RI:        j.RI,
			SZ:        j.SZ,
			Port_Low:  j.Port_Low,
			Port_High: j.Port_High,
			GT_Action: join_string(" ",
				j.AB.action_AB(receiver, v_Peer, inbound_type, inbound_direction),
				j.IF.action_IF(receiver, v_Peer, inbound_type, inbound_direction),
				j.RI.action_RI(receiver, v_Peer, inbound_type, inbound_direction),
				j.SZ.action_SZ(receiver, v_Peer, inbound_type, inbound_direction),
				action_Port(receiver, v_Peer, inbound_type, inbound_direction, 0, j.Port_Low, j.Port_High),
			),
			_Attribute_List: j._Attribute_List,
		})
	}
	return
}
func (receiver *cDB_Peer) parse_Route_Leak(v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak *cDB_Peer_RI_RO_Route_Leak) (outbound __W_Route_Leak_FromTo) {
	// outbound = make(__W_Route_Leak_FromTo)
	return parse_iDB_Route_Leak(nil, v_Peer, "", "", __W_Route_Leak_FromTo{
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

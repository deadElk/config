package main

import (
	"net/netip"
	"strconv"

	log "github.com/sirupsen/logrus"
)

func parse_JA(inbound *[]cDB_JA) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_ja[b.Name]; flag {
		case true:
			log.Warnf("Application '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ja[b.Name] = func() (outbound i_JA) {
			outbound = i_JA{
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
func parse_AB(inbound *[]cDB_AB) (ok bool) {
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
func parse_PL(inbound *[]cDB_PO_PL) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_pl[b.Name]; flag {
		case true:
			log.Warnf("Policy List '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_pl[b.Name] = func() (outbound i_PO_PL) {
			outbound = i_PO_PL{
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
func parse_PS(inbound *[]cDB_PO_PS) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_ps[b.Name]; flag {
		case true:
			log.Warnf("Policy Statement '%v' already exist; ACTION: skip.", b.Name)
			continue
		}
		i_ps[b.Name] = func() (outbound i_PO_PS) {
			outbound = i_PO_PS{
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
func parse_Peer(inbound *[]cDB_Peer) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_peer[b.ASN]; flag {
		case true:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN)
			continue
		}
		var (
			v_PName             = pad(&b.ASN, 10)
			v_Version           string
			v_Major             string
			v_Hostname          = parse_Peer_Hostname(&b)
			v_GT_List           = parse_Peer_GT_List(&b)
			v_IFM               = parse_Peer_IFM(&b)
			v_SP_Default_Policy = parse_Peer_SP_Options_Default_Policy(&b)
		)
		create_AB("O_AS"+_Name(v_PName), &_Service_Attributes{})
		create_AB("I_AS"+_Name(v_PName), &_Service_Attributes{})
		parse_AB(&b.AB)
		parse_JA(&b.JA)
		parse_PL(&b.PL)
		parse_PS(&b.PS)
		split_2_string(&b.Version, re_caps, &v_Version, &v_Major)
		var (
			v_RI         = parse_Peer_RI(&b)
			v_IF_2_RI    map[_Name]_Name
			v_Router_ID  = parse_Router_ID(&b)
			v_SZ         = parse_Peer_SZ(&b)
			v_NAT_Source map[_Type]i_NAT
			v_SP_Exact   []i_Rule_Set
			v_SP_Global  []i_Rule
			v_AB         map[_Name]*i_AB
			v_JA         map[_Name]*i_JA
			v_PL         map[_Name]*i_PO_PL
			v_PS         map[_Name]*i_PO_PS
		)
		i_peer[b.ASN] = func() (outbound i_Peer) {
			outbound = i_Peer{
				PName:         v_PName,
				Router_ID:     v_Router_ID,
				IF_2_RI:       v_IF_2_RI,
				VI:            map[_VI_ID]*i_VI{},
				VI_Peer_Left:  map[_VI_ID]*i_VI_Peer{},
				VI_Peer_Right: map[_VI_ID]*i_VI_Peer{},
				IFM:           v_IFM,
				RI:            v_RI,
				Hostname:      v_Hostname,
				Domain_Name:   b.Domain_Name,
				Version:       v_Version,
				Major:         parse_interface(strconv.ParseFloat(v_Major, 64)).(float64),
				Manufacturer:  b.Manufacturer,
				Model:         b.Model,
				Serial:        b.Serial,
				Root:          b.Root._Sanitize(16),
				GT_List:       v_GT_List,
				SZ:            v_SZ,
				NAT_Source:    v_NAT_Source,
				SP_Exact:      v_SP_Exact,
				SP_Global:     v_SP_Global,
				AB:            v_AB,
				JA:            v_JA,
				PL:            v_PL,
				PS:            v_PS,
				i_SP_Options: i_SP_Options{
					SP_Default_Policy: v_SP_Default_Policy,
				},
				_Service_Attributes: b._Service_Attributes,
			}
			return
		}()
	}
	return true
}
func parse_VI(inbound *[]cDB_VI) (ok bool) {
	for _, b := range *inbound {
		switch _, flag := i_vi[b.ID]; flag {
		case true:
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ID)
			continue
		}
		var (
			v_vi = func() (outbound i_VI) {
				outbound = i_VI{
					PName:               pad(&b.ID, 5),
					IPPrefix:            get_VI_IPPrefix(b.ID, 0),
					IKE_No_NAT:          false,
					IKE_GCM:             false,
					Type:                b.Type,
					Communication:       b.Communication,
					Route_Metric:        b.Route_Metric,
					PSK:                 b.PSK._Sanitize(64),
					_Service_Attributes: b._Service_Attributes,
				}
				return
			}()
			v_vi_peer = func() (outbound map[_VI_Peer_ID]i_VI_Peer) {
				outbound = make(map[_VI_Peer_ID]i_VI_Peer)
				for _, d := range b.Peer {
					switch _, flag := outbound[d.ID]; flag {
					case true:
						log.Warnf("VI '%v', Peer '%v' already exist; ACTION: skip.", b.ID, d.ID)
						continue
					}
					var (
						v_RI                = d.RI._Validate_RI(_Defaults[_mgmt_RI].(_Name))
						v_IF                = d.IF
						v_IP                = d.IP
						v_NAT               = netip.Addr{}
						v_IKE_Local_Address bool
					)
					outbound[d.ID] = i_VI_Peer{
						ASN:                 d.ASN,
						RI:                  v_RI,
						IF:                  v_IF,
						IP:                  v_IP,
						NAT:                 v_NAT,
						IKE_Local_Address:   v_IKE_Local_Address,
						Dynamic:             d.Dynamic,
						Inner_RI:            d.Inner_RI._Validate_RI(_Defaults[_mgmt_RI].(_Name)),
						Inner_IP:            get_VI_IPPrefix(b.ID, d.ID+1).Addr(),
						Inner_IPPrefix:      get_VI_IPPrefix(b.ID, d.ID+1),
						_Service_Attributes: d._Service_Attributes,
					}
				}
				return
			}()
		)
		i_vi[b.ID] = v_vi
		i_vi_peer[b.ID] = v_vi_peer
	}
	return true
}

func parse_Peer_Hostname(peer *cDB_Peer) (outbound _FQDN) {
	switch len(peer.Hostname) == 0 {
	case true:
		outbound = "gw_as" + _FQDN(pad(&peer.ASN, 10))
		log.Warnf("Peer '%v', Hostname '%v' is invalid; ACTION: use '%v'.", peer.ASN, peer.Router_ID, outbound)
	}
	return
}
func parse_Peer_GT_List(peer *cDB_Peer) (outbound []_Name) {
	switch len(peer.GT_List) == 0 {
	case true:
		return _Defaults[_GT_list].([]_Name)
	}
	for _, b := range peer.GT_List {
		outbound = append(outbound, _Name(b))
	}
	return
}
func parse_Router_ID(peer *cDB_Peer) (outbound netip.Addr) {
	switch peer.Router_ID.IsValid() {
	case false:
		log.Warnf("Peer '%v', Router_ID '%v' is invalid; ACTION: take lo0.0 first address.", peer.ASN, peer.Router_ID)
	}
	return
}
func parse_Peer_IFM(peer *cDB_Peer) (outbound map[_Name]i_Peer_IFM) {
	outbound = make(map[_Name]i_Peer_IFM)
	for _, b := range peer.IFM {
		outbound[b.Name] = i_Peer_IFM{
			Communication:       b.Communication,
			_Service_Attributes: b._Service_Attributes,
		}
	}
	return
}
func parse_Peer_RI(peer *cDB_Peer) (outbound map[_Name]i_Peer_RI) {
	outbound = make(map[_Name]i_Peer_RI)
	for _, b := range peer.RI {
		var (
			v_IP_2_IF = make(map[netip.Addr]_Name)
			v_IF      = func() (outbound map[_Name]i_Peer_RI_IF) {
				outbound = make(map[_Name]i_Peer_RI_IF)
				for _, d := range b.IF {
					switch _, flag := outbound[d.Name]; flag {
					case true:
						log.Warnf("Peer '%v', RI '%v', IF '%v' already exist; ACTION: ignore.", peer.ASN, b.Name, d.Name)
						continue
					}
					var (
						v_IF_IFM  string
						v_IF_IFsM string
					)
					split_2_string(&d.Name, re_dot, &v_IF_IFM, &v_IF_IFsM)
					outbound[d.Name] = i_Peer_RI_IF{
						IFM:           _Name(v_IF_IFM),
						IFsM:          _Name(v_IF_IFsM),
						Communication: d.Communication,
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
								add_2_AB(true, false, "OUTTER_LIST", f.IPPrefix.Addr(), f.NAT)
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
								add_2_AB(true, false, "OUTTER_LIST", f.IP, f.NAT)
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
			v_Leak = map[_Action]i_Peer_RI_RO_Leak_FromTo{
				_Action_import: {
					PL: func() (outbound []_Name) {
						for _, d := range b.From {
							outbound = append(outbound, d.PL)
						}
						return
					}(),
					_Service_Attributes: b._Service_Attributes,
				},
				_Action_export: {
					PL: func() (outbound []_Name) {
						for _, d := range b.To {
							outbound = append(outbound, d.PL)
						}
						return
					}(),
					_Service_Attributes: b._Service_Attributes,
				},
			}
		)
		outbound[b.Name] = i_Peer_RI{
			IP_2_IF:             v_IP_2_IF,
			IF:                  v_IF,
			RT:                  v_RT,
			Leak:                v_Leak,
			_Service_Attributes: b._Service_Attributes,
		}
	}
	return
}
func parse_Peer_SZ(peer *cDB_Peer) (outbound map[_Name]i_SZ) {
	outbound = make(map[_Name]i_SZ)
	for _, b := range peer.SZ {
		switch {
		case b.Name == _Defaults[_mgmt_RI].(_Name):
			log.Warnf("Peer '%v', SZ '%v' cannot be defined; ACTION: ignore.", peer.ASN, b.Name)
			continue
		case len(b.Screen) == 0:
		}
		outbound[b.Name] = i_SZ{
			Screen:              b.Screen,
			IF:                  nil,
			_Service_Attributes: b._Service_Attributes,
		}
	}
	return
}
func parse_Peer_SP_Options_Default_Policy(peer *cDB_Peer) (outbound _Action) {
	switch value := peer.SP_Options.Default_Policy; value {
	case _Action_permit_all, _Action_deny_all:
		return value
	case "":
		return _Defaults[_sp_efault_policy].(_Action)
	default:
		log.Warnf("Peer '%v', unknown default security policy '%v'; ACTION: use '%v'.", peer.ASN, value, _Defaults[_sp_efault_policy])
		return _Defaults[_sp_efault_policy].(_Action)
	}
}

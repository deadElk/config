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
		parse_AB(&b.AB)
		parse_JA(&b.JA)
		parse_PL(&b.PL)
		parse_PS(&b.PS)
		var (
			v_Version string
			v_Major   string
		)
		split_2_string(&b.Version, re_caps, &v_Version, &v_Major)
		i_peer[b.ASN] = func() (outbound i_Peer) {
			outbound = i_Peer{
				PName:         pad(&b.ASN, 10),
				Router_ID:     parse_Router_ID(&b),
				IF_2_RI:       map[_Name]_Name{},
				VI:            map[_VI_ID]*i_VI{},
				VI_Peer_Left:  map[_VI_ID]*i_VI_Peer{},
				VI_Peer_Right: map[_VI_ID]*i_VI_Peer{},
				IFM:           parse_Peer_IFM(&b),
				RI:            parse_Peer_RI(&b),
				Hostname:      parse_Peer_Hostname(&b),
				Domain_Name:   b.Domain_Name,
				Version:       v_Version,
				Major:         parse_interface(strconv.ParseFloat(v_Major, 64)).(float64),
				Manufacturer:  b.Manufacturer,
				Model:         b.Model,
				Serial:        b.Serial,
				Root:          b.Root._Sanitize(16),
				GT_List:       parse_Peer_GT_List(&b),
				SZ:            map[_Name]i_SZ{},
				NAT_Source:    map[_Type]i_NAT{},
				SP_Exact:      []i_Rule_Set{},
				SP_Global:     []i_Rule{},
				AB:            map[_Name]*i_AB{},
				JA:            map[_Name]*i_JA{},
				PL:            map[_Name]*i_PO_PL{},
				PS:            map[_Name]*i_PO_PS{},
				i_SP_Options: i_SP_Options{
					SP_Default_Policy: b.SP_Options.Default_Policy,
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
func parse_Peer_IFM(peer *cDB_Peer) (_ifm map[_Name]i_Peer_IFM) {
	_ifm = make(map[_Name]i_Peer_IFM)
	for _, b := range peer.IFM {
		_ifm[b.Name] = i_Peer_IFM{
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
						v_IFM  string
						v_IFsM string
					)
					split_2_string(&d.Name, re_dot, &v_IFM, &v_IFsM)
					outbound[d.Name] = i_Peer_RI_IF{
						IFM:           _Name(v_IFM),
						IFsM:          _Name(v_IFsM),
						Communication: d.Communication,
						// IP:                  map[netip.Prefix]i_Peer_RI_IF_IP{},
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
									case false:
										log.Warnf("Peer '%v', RI '%v', IF '%v', duplicate IP '%v' on IF '%v'; ACTION: ignore.", peer.ASN, b.Name, d.Name, f.IPPrefix, value)
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
						PARP:                map[netip.Prefix]i_Peer_RI_IF_PARP{},
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
								outbound[f.IF] = i_Peer_RI_RO_RT_GW{
									IP:                  f.IP,
									IF:                  f.IF,
									Table:               f.Table,
									Action:              f.Action,
									Action_Flag:         f.Action_Flag,
									Metric:              f.Metric,
									Preference:          f.Preference,
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

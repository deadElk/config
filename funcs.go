package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func hash(inbound *string) (outbound _ID) {
	var (
		value, flag = hash_cache.Load(*inbound)
	)
	switch {
	case flag && value.([_hash_Size]uint8) != outbound:
		return value.([_hash_Size]uint8)
	case flag:
		log.Warnf("Daemon: hash error - zero result from hash_cache.Load(%+v); ACTION: try to recover.", inbound)
	}
	switch value = sha3.Sum512([]uint8(*inbound)); value.([_hash_Size]uint8) != outbound {
	case true:
		hash_cache.Store(*inbound, value.([_hash_Size]uint8))
		return value.([_hash_Size]uint8)
	default:
		log.Panicf("Daemon: hash error - zero result from hash(%+v); ACTION: panic.", []uint8(*inbound))
	}
	return
}
func set_loglevel(inbound ...string) {
	switch len(inbound) == 0 {
	case false:
		switch loglevel, err := log.ParseLevel(inbound[0]); err == nil {
		case true:
			log.SetLevel(loglevel)
		default:
			log.SetLevel(_Defaults[_loglevel].(log.Level))
			// log.Warnf("verbosity level '%v' is not supported; ACTION: use '%v'.", *inbound[0], log.GetLevel())
		}
	default:
		log.SetLevel(_Defaults[_loglevel].(log.Level))
	}
}

func parse_interface(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch value == nil {
		case false:
			log.Debugf("'%v'", skip)
		}
	case bool:
		switch value {
		case false:
			log.Debugf("'%v'", skip)
		}
	}
	return inbound
}
func parse_interface_error(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch value == nil {
		case false:
			log.Debugf("'%v'", skip)
			return nil
		}
	case bool:
		switch value {
		case false:
			log.Debugf("'%v'", skip)
			return nil
		}
	}
	return inbound
}

func tabber(inbound string, tabs int) string {
	var (
		in_length  = len(inbound)
		tab_length = 8
		max_length = tabs*tab_length - 1
	)
	switch {
	case in_length > max_length:
		return inbound[:max_length]
	case in_length < max_length:
		var (
			add_tabs string
		)
		for counter := max_length - in_length - tab_length; counter >= 0; counter -= tab_length {
			add_tabs += "\t"
		}
		return inbound + add_tabs
	default:
		return inbound
	}
}

func split_string(inbound string, re *regexp.Regexp, target ...interface{}) {
	var (
		interim = re.Split(inbound, -1)
	)
	for a := 0; a < len(interim) && a < len(target); a++ {
		target[a] = interim[a]
	}
}

func get_VI_IPPrefix(vi_id _VI_ID, peer_id _VI_Peer_ID) netip.Prefix {
	var (
		b = make([]byte, 4)
	)
	binary.BigEndian.PutUint32(b, _Defaults[_VI_IPShift].(uint32)+uint32(vi_id*4)+uint32(peer_id))
	return netip.PrefixFrom(parse_interface(netip.AddrFromSlice(b)).(netip.Addr), 30)
}
func set_VI_IPPrefix(inbound ...netip.Prefix) {
	switch len(inbound) == 1 && inbound[0].IsValid() {
	case true:
		_Defaults[_VI_IPPrefix] = inbound[0]
	}
	_Defaults[_VI_IPShift] = binary.BigEndian.Uint32(_Defaults[_VI_IPPrefix].(netip.Prefix).Addr().AsSlice())
}
func set_Domain_Name(inbound ..._FQDN) {
	switch len(inbound) == 1 && len(inbound[0]) != 0 {
	case true:
		_Defaults[_domain_name] = inbound[0]
	}
}
func sum_string_gt_fm(inbound ...interface{}) (outbound string) {
	switch len(inbound) {
	case 0:
		return
	}
	for _, value := range inbound {
		switch element := value.(type) {
		case string:
			outbound += element
		case _Name:
			outbound += element.String()
		case _PName:
			outbound += element.String()
		case uint:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint8:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint16:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint32:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint64:
			outbound += strconv.FormatUint(element, 10)
		}
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
			// v_IP_2_IF = func() (outbound map[netip.Addr]_Name) {
			// 	outbound = make(map[netip.Addr]_Name)
			// 	return
			// }()
			v_IF = func() (outbound map[_Name]i_Peer_RI_IF) {
				outbound = make(map[_Name]i_Peer_RI_IF)
				for _, d := range b.IF {
					switch _, flag := outbound[d.Name]; flag {
					case true:
						log.Warnf("Peer '%v', RI '%v', IF '%v' already exist; ACTION: ignore.", peer.ASN, b.Name, d.Name)
						continue
					}
					outbound[d.Name] = i_Peer_RI_IF{
						IFM:                 "",
						IFsM:                "",
						Communication:       d.Communication,
						IP:                  map[netip.Prefix]i_Peer_RI_IF_IP{},
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
						GW: func() (outbound []i_Peer_RI_RO_RT_GW) {
							for _, f := range d.GW {
								outbound = append(outbound, i_Peer_RI_RO_RT_GW{
									IP:                  f.IP,
									IF:                  f.IF,
									Table:               f.Table,
									Action:              f.Action,
									Action_Flag:         f.Action_Flag,
									Metric:              f.Metric,
									Preference:          f.Preference,
									_Service_Attributes: f._Service_Attributes,
								})
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
func parse_Peer_Hostname(peer *cDB_Peer) (outbound _FQDN) {
	switch len(peer.Hostname) == 0 {
	case true:
		outbound = "gw_as" + _FQDN(peer.ASN._PName(10))
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

func read_GT() (ok bool) {
	var (
		dentry []os.DirEntry
		data   []byte
		err    error
	)
	switch dentry, err = os.ReadDir(_Defaults[_path_GT].(string)); err == nil {
	case false:
		log.Warnf("template director '%v' read error '%v'; ACTION: skip.", _Defaults[_path_GT], err)
		return
	}
	for _, fentry := range dentry {
		switch fentry.Type().IsRegular() {
		case false:
			continue
		}
		var (
			fsplit = re_dot.Split(fentry.Name(), -1)
		)
		switch len(fsplit) < 1 {
		case true:
			continue
		}
		switch fsplit[len(fsplit)-1] == "tmpl" {
		case false:
			continue
		}
		var (
			tname = _Name(fentry.Name()[:len(fentry.Name())-5])
		)
		switch data, err = os.ReadFile(_Defaults[_path_GT].(string) + "/" + fentry.Name()); err == nil {
		case false:
			log.Warnf("template '%v' read error '%v'; ACTION: skip.", tname, err)
			continue
		}
		switch _, flag := i_gt[tname]; flag {
		case true:
			log.Warnf("template '%v' already exist; ACTION: skip.", tname)
			continue
		}
		i_gt[tname] = i_GT{
			Content: _Content(data).trim_space(),
		}
	}
	return err == nil
}
func create_AB(ab_name _Name, sa *_Service_Attributes) (ok bool) {
	switch _, flag := i_ab[ab_name]; flag {
	case true:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = i_AB{
		Type:                _Type_set,
		Address:             nil,
		Addresses:           map[_Name]_Type{},
		_Service_Attributes: *sa,
	}
	return true
}
func add_2_AB(public, private bool, ab_name _Name, inbound ...interface{}) (ok bool) {
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
				i_ab[ab_name].Addresses[value] = _Type_set
			case _FQDN:
				ok = true
				i_ab[ab_name].Addresses[value._Name()] = _Type_fqdn
				add_2_AB(true, true, value._Name(), value)
			case netip.Prefix:
				var (
					ab = _Name(value.String())
				)
				ok = true
				i_ab[ab_name].Addresses[ab] = _Type_ipprefix
				add_2_AB(true, true, ab, value)
			}
		case flag:
			log.Warnf("AB '%+v''%+v', already exist; ACTION: skip.", ab_name, i_ab[ab_name])
			continue
		default:
			switch value := (address).(type) {
			case _FQDN:
				ok = true
				i_ab[ab_name] = i_AB{
					Type:    _Type_fqdn,
					Address: value,
				}
			case netip.Prefix:
				ok = true
				i_ab[ab_name] = i_AB{
					Type:    _Type_ipprefix,
					Address: value,
				}
			}
		}
	}
	return
}

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
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ASN._PName(10))
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
		split_string(b.Version, re_caps, v_Version, v_Major)
		log.Errorf("%v")
		i_peer[b.ASN] = func() (outbound i_Peer) {
			outbound = i_Peer{
				PName:         b.ASN._PName(10),
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
			log.Warnf("Peer '%v' already exist; ACTION: skip.", b.ID._PName(5))
			continue
		}
		var (
			v_vi = func() (outbound i_VI) {
				outbound = i_VI{
					PName:               b.ID._PName(5),
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
						log.Warnf("VI '%v', Peer '%v' already exist; ACTION: skip.", b.ID._PName(5), d.ID.String())
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

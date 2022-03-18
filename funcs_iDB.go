package main

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/netip"
	"sort"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
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
	sort.Slice(i_peer_list, func(i, j int) bool {
		return i_peer_list[i] < i_peer_list[j]
	})
	var (
		host_list string
	)
	for _, b := range i_peer_list {
		var (
			s_public  *[]_Name
			s_private *[]_Name
			ip_list   = "\t"
			s_target  = []string{0: i_peer[b].Router_ID.String()}
		)
		// todo: use strings_join
		s_private = i_peer[b].AB[_Name(strings_join("_", "I", i_peer[b].ASName))].get_address_list(s_private)
		s_public = i_peer[b].AB[_Name(strings_join("_", "O", i_peer[b].ASName))].get_address_list(s_public)
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

		host_list += func() (outbound string) {
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
				outbound += tabber(host, 2) +
					"\t####\t" +
					tabber(i_peer[b].PName.String(), 2) + "\t" +
					tabber(i_peer[b].Hostname.String(), 3) + "\t" +
					tabber(i_peer[b].Manufacturer+" "+i_peer[b].Model, 3) + "\t####\t" +
					ip_list + "\n"
			}
			outbound += "\n"
			return
		}()
	}
	i_write_file[_S_Dir[_dir_Config]].data[_S_File[_file_host_list]] = _Content(host_list)
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
		i_pl[a] = &i_PO_PL{GT_Action: strings_join(" ", _W_policy__options___prefix__list, a)}
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
		i_ps[_Name(strings_join("_", _W_aggregate, a))] = &i_PO_PS{
			Term: __i_PO_PS_Term{
				0: {
					Name: "REJECT",
					From: __i_PO_PS_From{
						0: {PL: a, Mask: _Mask_longer, GT_Action: strings_join(" ", _W_prefix__list__filter, a, _Mask_longer)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_load__balance, Action_Flag: _W_per__packet, GT_Action: strings_join(" ", _W_load__balance, _W_per__packet)},
					},
					GT_Action: strings_join(" ", _W_term, "REJECT"),
				},
			},
			GT_Action: strings_join(" ", _W_policy__options___policy__statement, _Name(strings_join("_", _W_aggregate, a))),
		}
	}

	for a, b := uint32(0), _Route_Weight(1); a <= uint32(_Route_Weight_max_rm); a, b = a+1, b<<int(_Route_Weight_bits_per_rm) {
		var (
			c = _Name(strings_join("_", _W_import_metric, pad(a, 2)))
			d = _Name(strings_join("_", _W_export_metric, pad(a, 2)))
		)
		i_ps[c] = &i_PO_PS{
			Term: __i_PO_PS_Term{
				0: {
					Name: "ACCEPT",
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: strings_join(" ", _W_then, _W_metric, _W_add, b)},
						1: {Action: _W_accept, GT_Action: strings_join(" ", _W_then, _W_accept)},
					},
					GT_Action: strings_join(" ", _W_term, "ACCEPT"),
				},
			},
			GT_Action: strings_join(" ", _W_policy__options___policy__statement, c),
		}
		i_ps[d] = &i_PO_PS{
			Term: __i_PO_PS_Term{
				0: {
					Name: "LOCAL",
					From: __i_PO_PS_From{
						0: {Protocol: _Protocol_access_internal, GT_Action: strings_join(" ", _W_from, _W_protocol, _Protocol_access_internal)},
						1: {Protocol: _Protocol_local, GT_Action: strings_join(" ", _W_from, _W_protocol, _Protocol_local)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_reject, GT_Action: strings_join(" ", _W_then, _W_reject)},
					},
					GT_Action: strings_join(" ", _W_term, "LOCAL"),
				},

				1: {
					Name: "DIRECT",
					From: __i_PO_PS_From{
						0: {Protocol: _Protocol_direct, GT_Action: strings_join(" ", _W_from, _W_protocol, _Protocol_direct)},
						1: {Protocol: _Protocol_static, GT_Action: strings_join(" ", _W_from, _W_protocol, _Protocol_static)},
						2: {Protocol: _Protocol_aggregate, GT_Action: strings_join(" ", _W_from, _W_protocol, _Protocol_aggregate)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Metric: b, GT_Action: strings_join(" ", _W_then, _W_metric, b)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: strings_join(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: strings_join(" ", _W_then, _W_accept)},
					},
					GT_Action: strings_join(" ", _W_term, "DIRECT"),
				},
				2: {
					Name: "INTERNAL",
					From: __i_PO_PS_From{
						0: {Route_Type: _Type_internal, GT_Action: strings_join(" ", _W_from, _W_route__type, _Type_internal)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: strings_join(" ", _W_then, _W_metric, _W_add, b+1)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: strings_join(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: strings_join(" ", _W_then, _W_accept)},
					},
					GT_Action: strings_join(" ", _W_term, "INTERNAL"),
				},
				3: {
					Name: "EXTERNAL",
					From: __i_PO_PS_From{
						0: {Route_Type: _Type_external, GT_Action: strings_join(" ", _W_from, _W_route__type, _Type_external)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: strings_join(" ", _W_then, _W_metric, _W_add, b)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: strings_join(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: strings_join(" ", _W_then, _W_accept)},
					},
					GT_Action: strings_join(" ", _W_term, "EXTERNAL"),
				},

				4: {
					Name: "REJECT",
					Then: __i_PO_PS_Then{
						0: {Action: _W_reject, GT_Action: strings_join(" ", _W_then, _W_reject)},
					},
					GT_Action: strings_join(" ", _W_term, "REJECT"),
				},
			},
			GT_Action: strings_join(" ", _W_policy__options___policy__statement, d),
		}
	}
	i_ps[_Name(_W_per__packet)] = &i_PO_PS{
		Term: __i_PO_PS_Term{
			0: {
				Name: "PER_PACKET",
				Then: __i_PO_PS_Then{
					0: {Action: _W_load__balance, Action_Flag: _W_per__packet, GT_Action: strings_join(" ", _W_load__balance, _W_per__packet)},
				},
				GT_Action: strings_join(" ", _W_term, "PER_PACKET"),
			},
		},
		GT_Action: strings_join(" ", _W_policy__options___policy__statement, _Name(_W_per__packet)),
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
		GT_Action: strings_join(" ", _W_security___address__book___global___address__set, ab_name),
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
		GT_Action: strings_join(" ", _W_security___address__book___global___address, ab_name, _W_dns__name, inbound),
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
		GT_Action: strings_join(" ", _W_security___address__book___global___address, ab_name, _W_address, inbound),
	}
	return true
}
func add_iDB_AB_Address_List(public, private bool, ab_name _Name, inbound ...interface{}) (ok bool) {
	var (
		interim_AB     = make(map[_Name]bool)
		interim_FQDN   = make(map[_FQDN]bool)
		interim_Prefix = make(map[netip.Prefix]bool)
	)
	for _, address := range inbound {
		switch value := (address).(type) {
		case netip.Addr:
			parse_iDB_AB_Prefix(public, private, ab_name, convert_netip_Addr_Prefix(&value), interim_Prefix)
		case netip.Prefix:
			parse_iDB_AB_Prefix(public, private, ab_name, value, interim_Prefix)
		case _FQDN:
			parse_iDB_AB_FQDN(public, private, ab_name, value, interim_FQDN)
		case _Name:
			parse_iDB_AB_Name(public, private, ab_name, value, interim_AB)
		case []netip.Addr:
			for _, f := range value {
				parse_iDB_AB_Prefix(public, private, ab_name, convert_netip_Addr_Prefix(&f), interim_Prefix)
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
				GT_Action: strings_join(" ", _W_address__set, a),
			}
			// create_iDB_AB_Set(a)
		}
		for a := range interim_FQDN {
			i_ab[ab_name].Set[_Name(a)] = &i_AB_Set{
				Type:      _Type_fqdn,
				GT_Action: strings_join(" ", _W_address, a),
			}
			create_iDB_AB_FQDN("", a)
		}
		for a := range interim_Prefix {
			i_ab[ab_name].Set[_Name(a.String())] = &i_AB_Set{
				Type:      _Type_ipprefix,
				GT_Action: strings_join(" ", _W_address, a),
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
			GT_Action:       strings_join(" ", _W_import, "[", v_RL_Import, "]"),
			_Attribute_List: route_leak[_W_import]._Attribute_List,
		}
	}
	switch {
	case len(v_RL_Export) != 0:
		outbound[_W_export] = &i_Route_Leak_FromTo{
			PS:              v_RL_Export,
			GT_Action:       strings_join(" ", _W_export, "[", v_RL_Export, "]"),
			_Attribute_List: route_leak[_W_export]._Attribute_List,
		}
	}
	return
}

func parse_GT() (not_ok bool) {
	for index, value := range i_peer {
		switch {
		case value.Reserved:
			continue
		}
		for _, gt_v := range value.GT_List {
			var (
				vBuf bytes.Buffer
			)
			switch vGT, err := template.New(gt_v.String()).Parse(string(i_read_file[_S_Dir[_dir_GT]].data[gt_v])); {
			case err == nil || vGT != nil:
				switch err = vGT.Execute(&vBuf, value); {
				case err != nil:
					log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: report.", index.String(), gt_v, err)
					not_ok = true
					continue
				}
				i_write_file[_S_Dir[_dir_Config]].data[value.ASName] = append(i_write_file[_S_Dir[_dir_Config]].data[value.ASName], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
			default:
				log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: report.", index.String(), gt_v, err)
				not_ok = true
				continue
			}
		}
	}
	return !not_ok
}

func parse_LDAP() (not_ok bool) {
	for _, b := range i_ldap {
		for _, d := range b.Domain {
			for _, f := range d.Raw_User.Entries {
				var (
					v_DN       = _DN(strings.ToLower(f.GetAttributeValue("entryDN")))
					v_IPPrefix = func() (outbound netip.Prefix) {
						outbound = parse_interface(netip.ParsePrefix(f.GetAttributeValue("ipHostNumber"))).(netip.Prefix)
						switch value, flag := b.M_IP_U[outbound]; {
						case !outbound.IsValid() || outbound.Bits() != _U_mask_per_user || !flag: // need ip assigment
							log.Warnf("LDAP DB inconsistent! UID '%v', incorrect ipHostNumber '%v' declared (must be IPPrefix/%v); ACTION: correct.", v_DN, outbound, _U_mask_per_user)
						case value == nil && flag:
							log.Warnf("UID '%v', ipHostNumber '%v'.", v_DN, outbound)
						}
						return
					}()
					v_GID_List       = __GN_LDAP_Domain_Group{}
					v_SSH_Public_Key = map[string]string{}
					v_P12            = map[string]string{}
					v_UID_Number     = _UID_Number(string_uint64(f.GetAttributeValue("uidNumber")))
					v_U              = &i_LDAP_Domain_User{
						UID_Number:     v_UID_Number,
						UID:            _UID(strings.ToLower(f.GetAttributeValue(b.User_CN))),
						GID_Number:     _GID_Number(string_uint64(f.GetAttributeValue("gidNumber"))),
						IPPrefix:       v_IPPrefix,
						GID_List:       v_GID_List,
						SSH_Public_Key: v_SSH_Public_Key,
						P12:            v_P12,
					}
				)
				d.User[v_UID_Number] = v_U
				b.M_CN_U[v_DN] = v_U
				b.M_IP_U[v_IPPrefix] = v_U
			}
		}
	}
	for _, b := range i_ldap {
		for _, d := range b.Domain {
			for _, f := range d.Raw_Group.Entries {
				var (
					v_GID_Number = _GID_Number(string_uint64(f.GetAttributeValue("gidNumber")))
					v_DN         = _DN(strings.ToLower(f.GetAttributeValue("entryDN")))
					v_G          = &i_LDAP_Domain_Group{
						GID_Number: v_GID_Number,
						GID:        _GID(strings.ToLower(f.GetAttributeValue(b.Group_CN))),
						UID_List: func() (outbound __UN_LDAP_Domain_User) {
							outbound = make(__UN_LDAP_Domain_User)
							for _, h := range f.GetAttributeValues("member") {
								var (
									u = b.M_CN_U[_DN(strings.ToLower(h))]
								)
								outbound[u.UID_Number] = u
							}
							return
						}(),
						Owner: func() (outbound __UN_LDAP_Domain_User) {
							outbound = make(__UN_LDAP_Domain_User)
							for _, h := range f.GetAttributeValues("owner") {
								var (
									u = b.M_CN_U[_DN(strings.ToLower(h))]
								)
								switch {
								case u == nil:
									log.Warnf("LDAP DB inconsistent! can't find owner UID '%v' of GID '%v'; ACTION: ignore.", h, v_DN)
									continue
								}
								outbound[u.UID_Number] = u
							}
							return
						}(),
					}
				)
				d.Group[v_GID_Number] = v_G
				b.M_CN_G[v_DN] = v_G
				for _, j := range d.Group[v_GID_Number].UID_List {
					j.GID_List[v_GID_Number] = v_G
				}
			}
		}
	}
	return !not_ok
}
func read_ldap() (not_ok bool) {
	for a, b := range i_ldap {
		func() {
			var (
				_ldap *ldap.Conn
				err   error
			)
			switch _ldap, err = ldap.Dial("tcp", a.Host); {
			case err != nil:
				log.Errorf("LDAP '%v' connect error: '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}
			defer _ldap.Close()
			switch err = _ldap.StartTLS(&tls.Config{InsecureSkipVerify: true}); {
			case err != nil:
				log.Errorf("LDAP '%v' TLS connect error: '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}
			switch err = _ldap.Bind(b.Bind_DN, b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v' bind error: '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}

			var (
				_db_request = ldap.NewSearchRequest(
					a.RawQuery,
					ldap.ScopeWholeSubtree,
					ldap.DerefAlways,
					0,
					0,
					false,
					_S_filter_db,
					[]string{"*", "+"},
					nil,
				)
				_db_result *ldap.SearchResult
			)
			switch _db_result, err = _ldap.Search(_db_request); {
			case err != nil:
				log.Errorf("LDAP '%v' search error: '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}
			for _, d := range _db_result.Entries {
				var (
					_dn = d.GetAttributeValue(b.DB_CN)
				)
				switch {
				case len(_dn) == 0:
					continue
				}
				log.Infof("LDAP '%v' search result: '%v'.", a.String(), _dn)
				switch _, flag := i_ldap_domain[_dn]; {
				case flag:
					log.Warnf("LDAP Domain '%v' already defined; ACTION: skip.", a)
					continue
				}

				var (
					_group_request = ldap.NewSearchRequest(
						_dn,
						ldap.ScopeWholeSubtree,
						ldap.DerefAlways,
						0,
						0,
						false,
						b.Group_Filter,
						[]string{"*", "+"},
						nil,
					)
					_group_result *ldap.SearchResult
				)
				switch _group_result, err = _ldap.Search(_group_request); {
				case err != nil:
					log.Fatalf("LDAP '%v' search error: '%v'; ACTION: fatal.", a.String(), err)
					not_ok = true
					continue
				}
				var (
					_user_request = ldap.NewSearchRequest(
						_dn,
						ldap.ScopeWholeSubtree,
						ldap.DerefAlways,
						0,
						0,
						false,
						b.User_Filter,
						[]string{"*", "+"},
						nil,
					)
					_user_result *ldap.SearchResult
				)
				switch _user_result, err = _ldap.Search(_user_request); {
				case err != nil:
					log.Fatalf("LDAP '%v' search error: '%v'; ACTION: fatal.", a.String(), err)
					not_ok = true
					continue
				}
				i_ldap_domain[_dn] = &i_LDAP_Domain{
					OLC: i_LDAP_Domain_OLC{
						DN: _DN(d.DN),
					},
					Group:     __GN_LDAP_Domain_Group{},
					User:      __UN_LDAP_Domain_User{},
					Raw_Group: _group_result,
					Raw_User:  _user_result,
				}
				i_ldap[a].Domain[_dn] = i_ldap_domain[_dn]
			}
		}()
	}
	return !not_ok
}
func write_ldap() (not_ok bool) {
	return !not_ok
}

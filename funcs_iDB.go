package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"text/template"
	"time"

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
	for _, b := range i_peer_list {
		var (
			s_public  *[]_Name
			s_private *[]_Name
			ip_list   = "\t"
			s_target  = []string{0: i_peer[b].Router_ID.String()} // todo: WTF????
		)
		s_private = i_peer[b].AB[_Name(join_string("_", "I", i_peer[b].ASName))].get_address_list(s_private)
		s_public = i_peer[b].AB[_Name(join_string("_", "O", i_peer[b].ASName))].get_address_list(s_public)
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
			i_file.append(_dir_Config, _file_host_list, "\n", tabber(host, 2)+
				"\t####\t"+
				tabber(i_peer[b].PName.String(), 2)+"\t"+
				tabber(i_peer[b].Hostname.String(), 3)+"\t"+
				tabber(i_peer[b].Manufacturer+" "+i_peer[b].Model, 3)+"\t####\t"+
				ip_list)
		}
		i_file.append(_dir_Config, _file_host_list, "", "\n")
	}
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
		i_pl[a] = &i_PO_PL{GT_Action: join_string(" ", _W_policy__options___prefix__list, a)}
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
		i_ps[_Name(join_string("_", _W_aggregate, a))] = &i_PO_PS{
			Term: __i_PO_PS_Term{
				0: {
					Name: "REJECT",
					From: __i_PO_PS_From{
						0: {PL: a, Mask: _Mask_longer, GT_Action: join_string(" ", _W_prefix__list__filter, a, _Mask_longer)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_load__balance, Action_Flag: _W_per__packet, GT_Action: join_string(" ", _W_load__balance, _W_per__packet)},
					},
					GT_Action: join_string(" ", _W_term, "REJECT"),
				},
			},
			GT_Action: join_string(" ", _W_policy__options___policy__statement, _Name(join_string("_", _W_aggregate, a))),
		}
	}

	for a, b := uint32(0), _INet_Routing(1); a <= uint32(_Route_Weight_max_rm); a, b = a+1, b<<int(_Route_Weight_bits_per_rm) {
		var (
			c = _Name(join_string("_", _W_import_metric, pad(a, 2)))
			d = _Name(join_string("_", _W_export_metric, pad(a, 2)))
		)
		i_ps[c] = &i_PO_PS{
			Term: __i_PO_PS_Term{
				0: {
					Name: "ACCEPT",
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, _W_add, b)},
						1: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "ACCEPT"),
				},
			},
			GT_Action: join_string(" ", _W_policy__options___policy__statement, c),
		}
		i_ps[d] = &i_PO_PS{
			Term: __i_PO_PS_Term{
				0: {
					Name: "LOCAL",
					From: __i_PO_PS_From{
						0: {Protocol: _Protocol_access_internal, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_access_internal)},
						1: {Protocol: _Protocol_local, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_local)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_reject, GT_Action: join_string(" ", _W_then, _W_reject)},
					},
					GT_Action: join_string(" ", _W_term, "LOCAL"),
				},

				1: {
					Name: "DIRECT",
					From: __i_PO_PS_From{
						0: {Protocol: _Protocol_direct, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_direct)},
						1: {Protocol: _Protocol_static, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_static)},
						2: {Protocol: _Protocol_aggregate, GT_Action: join_string(" ", _W_from, _W_protocol, _Protocol_aggregate)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, b)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: join_string(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "DIRECT"),
				},
				2: {
					Name: "INTERNAL",
					From: __i_PO_PS_From{
						0: {Route_Type: _Type_internal, GT_Action: join_string(" ", _W_from, _W_route__type, _Type_internal)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, _W_add, b+1)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: join_string(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "INTERNAL"),
				},
				3: {
					Name: "EXTERNAL",
					From: __i_PO_PS_From{
						0: {Route_Type: _Type_external, GT_Action: join_string(" ", _W_from, _W_route__type, _Type_external)},
					},
					Then: __i_PO_PS_Then{
						0: {Action: _W_metric, Action_Flag: _W_add, Metric: b, GT_Action: join_string(" ", _W_then, _W_metric, _W_add, b)},
						1: {Action: _W_next__hop, Action_Flag: _W_self, GT_Action: join_string(" ", _W_then, _W_next__hop, _W_self)},
						2: {Action: _W_accept, GT_Action: join_string(" ", _W_then, _W_accept)},
					},
					GT_Action: join_string(" ", _W_term, "EXTERNAL"),
				},

				4: {
					Name: "REJECT",
					Then: __i_PO_PS_Then{
						0: {Action: _W_reject, GT_Action: join_string(" ", _W_then, _W_reject)},
					},
					GT_Action: join_string(" ", _W_term, "REJECT"),
				},
			},
			GT_Action: join_string(" ", _W_policy__options___policy__statement, d),
		}
	}
	i_ps[_Name(_W_per__packet)] = &i_PO_PS{
		Term: __i_PO_PS_Term{
			0: {
				Name: "PER_PACKET",
				Then: __i_PO_PS_Then{
					0: {Action: _W_load__balance, Action_Flag: _W_per__packet, GT_Action: join_string(" ", _W_load__balance, _W_per__packet)},
				},
				GT_Action: join_string(" ", _W_term, "PER_PACKET"),
			},
		},
		GT_Action: join_string(" ", _W_policy__options___policy__statement, _Name(_W_per__packet)),
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
		GT_Action: join_string(" ", _W_security___address__book___global___address__set, ab_name),
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
		GT_Action: join_string(" ", _W_security___address__book___global___address, ab_name, _W_dns__name, inbound),
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
		GT_Action: join_string(" ", _W_security___address__book___global___address, ab_name, _W_address, inbound),
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
				GT_Action: join_string(" ", _W_address__set, a),
			}
			// create_iDB_AB_Set(a)
		}
		for a := range interim_FQDN {
			i_ab[ab_name].Set[_Name(a)] = &i_AB_Set{
				Type:      _Type_fqdn,
				GT_Action: join_string(" ", _W_address, a),
			}
			create_iDB_AB_FQDN("", a)
		}
		for a := range interim_Prefix {
			i_ab[ab_name].Set[_Name(a.String())] = &i_AB_Set{
				Type:      _Type_ipprefix,
				GT_Action: join_string(" ", _W_address, a),
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
			GT_Action:       join_string(" ", _W_import, "[", v_RL_Import, "]"),
			_Attribute_List: route_leak[_W_import]._Attribute_List,
		}
	}
	switch {
	case len(v_RL_Export) != 0:
		outbound[_W_export] = &i_Route_Leak_FromTo{
			PS:              v_RL_Export,
			GT_Action:       join_string(" ", _W_export, "[", v_RL_Export, "]"),
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
				vBuf = new(bytes.Buffer)
			)
			switch vGT, err := template.New(gt_v.String()).Parse(i_file.get(_dir_GT, _File_Name(gt_v)).String()); {
			case err == nil || vGT != nil:
				switch err = vGT.Execute(vBuf, value); {
				case err != nil:
					log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: report.", index.String(), gt_v, err)
					not_ok = true
					continue
				}
				i_file.append(_dir_Config, _File_Name(value.ASName), "\n", vBuf)
			default:
				log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: report.", index.String(), gt_v, err)
				not_ok = true
				continue
			}
		}
	}
	return !not_ok
}

func get_LDAP_Entries(inbound *ldap.Entry, list ...string) (not_ok bool, outbound _SKV) {
	outbound = make(_SKV)
	var (
		t = make(_SKV)
	)
	for _, b := range list {
		t[b] = []string{}
		var (
			attr = inbound.GetAttributeValues(b)
		)
		for _, d := range attr {
			switch {
			case len(d) == 0:
				continue
			}
			t[b] = append(t[b], d)
		}

		switch {

		case b == _skv_ca && len(t[_skv_ca]) < 1:
			log.Debugf("DN '%v': not enough CAs defined in LDAP; ACTION: generate the rest.", inbound.DN)
			outbound[_skv_ca] = make([]string, 1, 1)
		case b == _skv_ca && len(t[_skv_ca]) == 1:
			outbound[_skv_ca] = make([]string, 1, 1)
			outbound[_skv_ca] = t[_skv_ca]
		case b == _skv_ca && len(t[_skv_ca]) > 1:
			log.Errorf("DN '%v': too many CAs defined in LDAP; ACTION: report.", inbound.DN)
			not_ok = true

		case b == _skv_crl && len(t[_skv_crl]) < 1:
			log.Debugf("DN '%v': not enough CRLs defined in LDAP; ACTION: generate the rest.", inbound.DN)
			outbound[_skv_crl] = make([]string, 1, 1)
		case b == _skv_crl && len(t[_skv_crl]) == 1:
			outbound[_skv_crl] = make([]string, 1, 1)
			outbound[_skv_crl] = t[_skv_crl]
		case b == _skv_crl && len(t[_skv_crl]) > 1:
			log.Errorf("DN '%v': too many CRLs defined in LDAP; ACTION: report.", inbound.DN)
			not_ok = true

		case b == _skv_p12 && len(t[_skv_p12]) < int(_UIx_IPx):
			log.Debugf("DN '%v': not enough user P12s defined in LDAP; ACTION: check actual data, generate the rest.", inbound.DN)
			outbound[_skv_p12] = make([]string, _UIx_IPx, _UIx_IPx)
			outbound[_skv_p12] = t[_skv_p12]
		case b == _skv_p12 && len(t[_skv_p12]) == int(_UIx_IPx):
			outbound[_skv_p12] = make([]string, _UIx_IPx, _UIx_IPx)
			outbound[_skv_p12] = t[_skv_p12]
		case b == _skv_p12 && len(t[_skv_p12]) > int(_UIx_IPx):
			log.Warnf("DN '%v': too many user P12s defined in LDAP; ACTION: check actual data.", inbound.DN)
			// log.Warnf("DN '%v': too many user P12s defined in LDAP; ACTION: report.", inbound.DN)
			// not_ok = true

		case b == _skv_ip && len(t[_skv_ip]) < 1:
			log.Warnf("DN '%v': not enough IPPrefixes defined in LDAP; ACTION: generate the rest.", inbound.DN)
			outbound[_skv_ip] = make([]string, 1, 1)
		case b == _skv_ip && len(t[_skv_ip]) == 1:
			outbound[_skv_ip] = make([]string, 1, 1)
			outbound[_skv_ip] = t[_skv_ip]
		case b == _skv_ip && len(t[_skv_ip]) > 1:
			log.Errorf("DN '%v': too many IPPrefixes defined in LDAP; ACTION: report.", inbound.DN)
			not_ok = true

		case b == _skv_luri:
			outbound[_skv_luri] = t[_skv_luri]

		case b == _skv_ssh:
			outbound[_skv_ssh] = t[_skv_ssh]

		}

	}
	return
}

func parse_LDAP() (not_ok bool) {
	for a, b := range i_ldap {
		for _, d := range b.Domain {
			d.FQDN = b._DN_FQDN(d.DN)
			for _, f := range d.Raw_DC.Entries {
				not_ok, d.SKV = get_LDAP_Entries(f, _skv_ca, _skv_crl)
				d.Entry = f
			}

			switch _, flag := i_PKI.CA_Node[d.FQDN]; {
			case flag:
				log.Errorf("PKI DB '%v' already defined; ACTION: report.", d.FQDN)
				not_ok = true
			}
			i_PKI.CA_Node[d.FQDN] = &_PKI_CA_Node{
				FQDN:     d.FQDN,
				CA:       nil,
				CA_Chain: nil,
				CA_Node:  __FQDN_PKI_CA_Node{},
				Cert:     nil,
				Key:      nil,
				CRL:      nil,
				DER: &_PKI_CA_Node_DER{
					Cert: _DER(*i_file.get(_dir_PKI_Cert, _File_Name(d.FQDN))),
					Key:  _DER(*i_file.get(_dir_PKI_Key, _File_Name(d.FQDN))),
					CRL:  _DER(*i_file.get(_dir_PKI_CRL, _File_Name(d.FQDN))),
				},
				Node: __FQDN_PKI_Node{},
			}
			//					Cert: _DER(d.SKV[_skv_ca][0]),
			//					Key:  _DER(*i_file[_dir_PKI_Key].data[_File_Name(d.FQDN)]),
			//					CRL:  _DER(d.SKV[_skv_crl][0]),
			switch {
			case i_PKI.CA_Node[d.FQDN].parse_DER(&x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject: pkix.Name{
					Organization: []string{d.FQDN.String()},
					CommonName:   d.FQDN.String(),
					Names:        nil,
					ExtraNames:   nil,
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				IsCA:                  true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
				CRLDistributionPoints: []string{join_string("", "http://", join_string(".", "ns", d.FQDN), "/crl.pem")},
				DNSNames:              []string{d.FQDN.String()},
				EmailAddresses:        []string{join_string("@", "ns", d.FQDN)},
				IPAddresses:           nil,
			}):
				d.modify(_skv_acrl, []string{i_PKI.CA_Node[d.FQDN].DER.CRL.String()})
				d.modify(_skv_ca, []string{i_PKI.CA_Node[d.FQDN].DER.Cert.String()})
				d.modify(_skv_crl, []string{i_PKI.CA_Node[d.FQDN].DER.CRL.String()})
				i_file.put(_dir_PKI_Cert, _File_Name(d.FQDN), "", i_PKI.CA_Node[d.FQDN].DER.Cert)
				i_file.put(_dir_PKI_Key, _File_Name(d.FQDN), "", i_PKI.CA_Node[d.FQDN].DER.Key)
				i_file.put(_dir_PKI_CRL, _File_Name(d.FQDN), "", i_PKI.CA_Node[d.FQDN].DER.CRL)
			}
			d.PKI = i_PKI.CA_Node[d.FQDN]

			for _, f := range d.Raw_User.Entries {
				var (
					v_U = &i_LDAP_Domain_User{
						LDAP:       b,
						DN:         _DN(f.GetAttributeValue("entryDN")),
						Domain:     d,
						Entry:      f,
						FQDN:       "",
						GID_List:   __GN_LDAP_Domain_Group{},
						GID_Number: _GID_Number(string_uint64(f.GetAttributeValue("gidNumber"))),
						IPPrefix:   netip.Prefix{},
						Modify:     nil,
						SKV:        nil,
						UID:        _UID(f.GetAttributeValue(b.User_CN)),
						UID_Number: _UID_Number(string_uint64(f.GetAttributeValue("uidNumber"))),
						PKI:        nil,
					}
				)
				switch {
				case v_U.UID_Number == 0:
					log.Errorf("LDAP DB '%v' inconsistent! UID '%v': UID_Number is '%v'; ACTION: report.", a.String(), v_U.DN, v_U.GID_Number)
					not_ok = true
					fallthrough
				case v_U.GID_Number == 0:
					log.Warnf("LDAP DB '%v' inconsistent! primary GID_Number is not defined for UID '%v'; ACTION: skip user.", a.String(), f.DN)
					continue
				}
				switch v_ipHostNumber := f.GetAttributeValue("ipHostNumber"); { // modification candidate -> user's ip space
				case len(v_ipHostNumber) != 0:
					var (
						v_IPPrefix = parse_interface(netip.ParsePrefix(f.GetAttributeValue("ipHostNumber"))).(netip.Prefix)
					)
					switch value, flag := i_ui_ip[v_IPPrefix]; {
					case flag && value.User == nil: // ip found and free
						log.Debugf("UID '%v', ipHostNumber '%v'.", v_U.DN, v_IPPrefix)
						v_U.IPPrefix = v_IPPrefix
						i_ui_ip[v_U.IPPrefix].User = v_U
					case flag && value.User != nil: // ip found but occupied, so need ip assigment
						log.Warnf("LDAP DB '%v' inconsistent! UID '%v', ipHostNumber '%v' occupied by '%v'; ACTION: find new.", a.String(), v_U.DN, v_IPPrefix, value.User.DN)
					}
				default: // ip not found, so need ip assigment
					log.Debugf("LDAP '%v': UID '%v', ipHostNumber not defined; ACTION: find new.", a.String(), v_U.DN)
				}

				v_U.PKI = make(__PKI_Node, _UIx_IPx, _UIx_IPx)
				not_ok, v_U.SKV = get_LDAP_Entries(f, _skv_ssh, _skv_p12, _skv_luri)
				v_U.FQDN = b._DN_FQDN(v_U.DN)

				d.User[v_U.UID_Number] = v_U
				b.M_CN_U[v_U.DN] = v_U
			}
		}
	}

	for a, b := range i_ldap {
		for _, d := range b.Domain {
			for _, f := range d.Raw_Group.Entries {
				var (
					v_G = &i_LDAP_Domain_Group{
						LDAP:           b,
						DN:             _DN(f.GetAttributeValue("entryDN")),
						Domain:         d,
						Entry:          f,
						FQDN:           "",
						GID:            _GID(f.GetAttributeValue(b.Group_CN)),
						GID_List:       nil,
						GID_Number:     _GID_Number(string_uint64(f.GetAttributeValue("gidNumber"))),
						Modify:         nil,
						Owner_GID_List: nil,
						Owner_UID_List: nil,
						SKV:            nil,
						UID_List:       nil,
						PKI:            nil,
					}
					v_UID_List       = make(__UN_LDAP_Domain_User)
					v_GID_List       = make(__GN_LDAP_Domain_Group) // todo
					v_Owner_UID_List = make(__UN_LDAP_Domain_User)
					v_Owner_GID_List = make(__GN_LDAP_Domain_Group) // todo
				)
				for _, h := range f.GetAttributeValues("member") {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil:
						log.Errorf("LDAP DB inconsistent! can't find member UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						not_ok = true
						continue
					}
					v_UID_List[u.UID_Number] = u
				}
				for _, h := range f.GetAttributeValues("owner") {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil:
						log.Errorf("LDAP DB inconsistent! can't find owner UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						not_ok = true
						continue
					}
					v_Owner_UID_List[u.UID_Number] = u
				}

				switch {
				case v_G.GID_Number == 0:
					log.Errorf("LDAP DB inconsistent! GID '%v': GID_Number is '%v'; ACTION: report.", v_G.DN, v_G.GID_Number)
					not_ok = true
				}

				v_G.FQDN = b._DN_FQDN(v_G.DN)

				v_G.UID_List = v_UID_List
				v_G.GID_List = v_GID_List
				v_G.Owner_UID_List = v_Owner_UID_List
				v_G.Owner_GID_List = v_Owner_GID_List

				not_ok, v_G.SKV = get_LDAP_Entries(f, _skv_p12, _skv_luri)

				d.Group[v_G.GID_Number] = v_G
				b.M_CN_G[v_G.DN] = v_G
				for _, j := range d.Group[v_G.GID_Number].UID_List {
					j.GID_List[v_G.GID_Number] = v_G
				}
			}
			for _, f := range d.User {
				switch {
				case f.GID_Number != 0 && d.Group[f.GID_Number] == nil:
					log.Errorf("LDAP DB inconsistent! can't find primary GID_Number '%v' for UID '%v'; ACTION: report.", f.GID_Number, f.DN)
					not_ok = true
				}
				switch _, flag := i_ui_ip[f.IPPrefix]; {
				case flag && i_ui_ip[f.IPPrefix].User == f:
					continue
				}
				var (
					v_IPPrefix = func() (outbound netip.Prefix) { // modification candidate -> user's ip space
						for y, z := range i_ui_ip {
							switch {
							case z.User == nil:
								f.modify(_skv_ip, []string{y.String()})
								log.Infof("LDAP '%v': UID '%v', found new ipHostNumber '%v'; ACTION: report.", a.String(), f.DN, y)
								return y
							}
						}
						log.Fatalf("not enough user ip space")
						not_ok = true
						return
					}()
				)
				f.IPPrefix = v_IPPrefix
			}
		}
	}

	for a, b := range i_ldap { // third pass, fill PKI with known data or generate new
		for _, d := range b.Domain {

			// for _, f := range d.Group {
			// }
			for _, f := range d.User {
				switch f.UID {
				case "lom":
				default:
					continue
				}

				for _, h := range f.SKV[_skv_p12] {
					var (
						v_P12 = _P12(h)
					)
					switch v_FQDN, status := v_P12.get_FQDN(); {
					case status:
						switch _, flag := i_PKI.CA_Node[d.FQDN].Node[v_FQDN]; {
						case flag:
							log.Errorf("LDAP DB '%v': P12 for '%v' already defined; ACTION: report.", a.String(), v_FQDN)
							not_ok = true
							continue
						}
						i_PKI.CA_Node[d.FQDN].Node[v_FQDN] = &_PKI_Node{
							FQDN: v_FQDN,
							CA:   i_PKI.CA_Node[d.FQDN],
							Cert: nil,
							Key:  nil,
							DER:  nil,
							P12:  v_P12,
						}
					}
				}

				var (
					changed bool
				)
				for g := 0; g < int(_UIx_IPx); g++ {
					var (
						h = f.FQDN
					)
					switch {
					case g >= 1 && g <= len(_re_lower_case):
						h = _FQDN(join_string(".", string(rune(g+96)), h))
					case g > len(_re_lower_case):
						h = _FQDN(join_string(".", "x"+pad(strconv.FormatInt(int64(g), 16), 2), h))
					}
					switch _, flag := i_PKI.CA_Node[d.FQDN].Node[h]; {
					case !flag:
						i_PKI.CA_Node[d.FQDN].Node[h] = &_PKI_Node{FQDN: h, CA: i_PKI.CA_Node[d.FQDN]}
					}
					changed = i_PKI.CA_Node[d.FQDN].Node[h].parse_P12(&x509.Certificate{
						SerialNumber: big.NewInt(time.Now().UnixNano()),
						Subject: pkix.Name{
							Organization: []string{d.FQDN.String()},
							CommonName:   h.String(),
							Names:        nil,
							ExtraNames:   nil,
						},
						NotBefore:   time.Now(),
						NotAfter:    time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
						IsCA:        false,
						ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
						KeyUsage:    x509.KeyUsageDigitalSignature,
						// DNSNames:       []string{i.String()},
						EmailAddresses: []string{h.String()},
						// IPAddresses:    nil,
					})
					f.PKI[g] = i_PKI.CA_Node[d.FQDN].Node[h]
				}
				switch {
				case changed:
					var (
						changes = make([]string, _UIx_IPx, _UIx_IPx)
					)
					for k := 0; k < int(_UIx_IPx); k++ {
						changes[k] = f.PKI[k].P12.String()
					}
					f.modify(_skv_p12, changes)
				}
			}
		}
	}
	switch {
	case not_ok:
		return not_ok
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
			// switch _ldap, err = ldap.DialURL(b.URL.String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); {
			switch _ldap, err = ldap.DialURL(a.String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); {
			case err != nil:
				log.Errorf("LDAP '%v': connect error '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}
			defer _ldap.Close()
			switch err = _ldap.Bind(b.Bind_DN.String(), b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v': bind error '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}

			var (
				_db_request = ldap.NewSearchRequest(
					b.URL.Path[1:],
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
				log.Errorf("LDAP '%v': search error '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}
			for _, d := range _db_result.Entries {
				var (
					_dn = _DN(d.GetAttributeValue(b.DB_CN))
				)
				switch {
				case len(_dn) == 0:
					continue
				}
				switch {
				case _dn != "dc=domain,dc=tld":
					continue
				}
				log.Infof("LDAP '%v' search result: '%v'.", a.String(), _dn)
				switch _, flag := i_ldap_domain[_dn]; {
				case flag:
					log.Warnf("LDAP '%v': domain already defined; ACTION: skip.", a)
					continue
				}

				var (
					_dc_request = ldap.NewSearchRequest(
						_dn.String(),
						ldap.ScopeWholeSubtree,
						ldap.DerefAlways,
						0,
						0,
						false,
						b.DC_Filter,
						[]string{"*", "+"},
						nil,
					)
					_dc_result *ldap.SearchResult
				)
				switch _dc_result, err = _ldap.Search(_dc_request); {
				case err != nil:
					log.Fatalf("LDAP '%v': search error '%v'; ACTION: fatal.", a.String(), err)
					not_ok = true
					continue
				}

				var (
					_group_request = ldap.NewSearchRequest(
						_dn.String(),
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
					log.Fatalf("LDAP '%v': search error '%v'; ACTION: fatal.", a.String(), err)
					not_ok = true
					continue
				}

				var (
					_user_request = ldap.NewSearchRequest(
						_dn.String(),
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
					log.Fatalf("LDAP '%v': search error '%v'; ACTION: fatal.", a.String(), err)
					not_ok = true
					continue
				}

				i_ldap_domain[_dn] = &i_LDAP_Domain{
					LDAP:      b,
					DN:        _dn,
					Group:     __GN_LDAP_Domain_Group{},
					OLC:       &i_LDAP_Domain_OLC{DN: _DN(d.DN)},
					Raw_DC:    _dc_result,
					Raw_Group: _group_result,
					Raw_User:  _user_result,
					User:      __UN_LDAP_Domain_User{},
				}
				i_ldap[a].Domain[_dn] = i_ldap_domain[_dn]
			}
		}()
	}
	return !not_ok
}
func write_ldap() (not_ok bool) {
	for a, b := range i_ldap {
		func() {
			var (
				_ldap *ldap.Conn
				// _result *ldap.ModifyResult
				do_modify = func(inbound *ldap.ModifyRequest) {
					switch {
					case inbound != nil:
						log.Warnf("LDAP '%v': found modification for '%v'; ACTION: upload.", a.String(), inbound.DN)
						switch err := _ldap.Modify(inbound); {
						case err != nil:
							log.Errorf("LDAP '%v': '%v' modification error: '%v'; ACTION: report.", a.String(), inbound.DN, err)
							// not_ok = true
						default:
							log.Infof("LDAP '%v': done modification for '%v'; ACTION: report.", a.String(), inbound.DN)
						}
					}
				}
				err error
			)
			// switch _ldap, err = ldap.DialURL(b.URL.String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); {
			switch _ldap, err = ldap.DialURL(a.String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); {
			case err != nil:
				log.Errorf("LDAP '%v': connect error '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}
			defer _ldap.Close()
			switch err = _ldap.Bind(b.Bind_DN.String(), b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v': bind error '%v'; ACTION: skip.", a.String(), err)
				not_ok = true
				return
			}

			for _, d := range b.Domain {
				do_modify(d.Modify)
				for _, f := range d.Group {
					do_modify(f.Modify)
				}
				for _, f := range d.User {
					do_modify(f.Modify)
				}
			}
		}()
	}
	return !not_ok
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func ldap_modify_Add_Attr(inbound *ldap.Entry, outbound *ldap.ModifyRequest, attrName string) {
	var (
		attrType = _W_objectClass.String()
		attrVal  string
	)
	switch attrName {
	case _skv_ipHostNumber:
		attrVal = "ipHost"
	case _skv_labeledURI:
		attrVal = "labeledURIObject"
	case _skv_CA, _skv_CRL:
		attrVal = "pkiCA"
		// 	attrVal = "certificationAuthority"
	case _skv_P12:
		return
	default:
		return
	}
	for _, b := range inbound.GetAttributeValues(attrType) { // todo: attr caching?
		switch {
		case b == attrVal:
			return
		}
	}
	for _, b := range outbound.Changes {
		switch {
		case b.Modification.Type == attrType:
			for _, d := range b.Modification.Vals {
				switch {
				case d == attrVal:
					return
				}
			}
		}
	}
	outbound.Add(attrType, []string{attrVal})
}
func read_ldap() (status bool) {
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
				status = true
				return
			}
			defer _ldap.Close()
			switch err = _ldap.Bind(b.Bind_DN.String(), b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v': bind error '%v'; ACTION: skip.", a.String(), err)
				status = true
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
				status = true
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
					status = true
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
					status = true
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
					status = true
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
	return !status
}
func write_ldap() (status bool) {
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
							// status = true
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
				status = true
				return
			}
			defer _ldap.Close()
			switch err = _ldap.Bind(b.Bind_DN.String(), b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v': bind error '%v'; ACTION: skip.", a.String(), err)
				status = true
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
	return !status
}
func get_LDAP_SKV(inbound *ldap.Entry, list map[string]int) (status bool, outbound _SKV) {
	outbound = make(_SKV)
	var (
		t = make(_SKV)
	)
	for a, b := range list {
		var (
			attr   = inbound.GetAttributeValues(a)
			flag   = b != 0
			filter = make(map[string]bool)
		)
		for _, d := range attr {
			switch {
			case len(d) == 0 || filter[d]:
				continue
			}
			filter[d] = true
		}
		for d := range filter {
			t[a] = append(t[a], d)
		}

		sort.Strings(t[a])
		switch {
		case flag:
			switch {
			case flag && len(t[a]) < b:
				log.Debugf("DN '%v': not enough '%v' defined in LDAP; ACTION: generate the rest.", inbound.DN, a)
				// outbound[a] = make([]string, b, b)
			case flag && len(t[a]) == b:
				// outbound[a] = make([]string, b, b)
				outbound[a] = t[a]
			case flag && len(t[a]) > b:
				log.Errorf("DN '%v': too many '%v' defined in LDAP; ACTION: report.", inbound.DN, a)
				status = true
			}
		default:
			outbound[a] = t[a]
		}
	}
	return
}

func parse_LDAP() (status bool) {
	for a, b := range i_ldap {
		for _, d := range b.Domain {
			d.FQDN = b._DN_FQDN(d.DN)
			for _, f := range d.Raw_DC.Entries {
				var (
					f_SKV, v_SKV = get_LDAP_SKV(f, map[string]int{_skv_CA: 1, _skv_CRL: 1})
				)
				status = status || f_SKV
				d.SKV = v_SKV
				d.Entry = f
			}

			switch _, flag := i_PKI_DB.CA_Node[d.FQDN]; {
			case flag:
				log.Errorf("PKI DB '%v' already defined; ACTION: report.", d.FQDN)
				status = true
			}
			i_PKI_DB.CA_Node[d.FQDN] = &_PKI_CA_Node{
				FQDN:     d.FQDN,
				CA:       nil,
				CA_Chain: nil,
				CA_Node:  __FQDN_PKI_CA_Node{},
				Cert:     nil,
				Key:      nil,
				CRL:      nil,
				DER: &_PKI_CA_Node_DER{
					Cert: _DER(*i_file.get(_dir_PKI_CA, _File_Name(d.FQDN+".crt"))), // _DER(d.SKV[_skv_CA][0]),
					Key:  _DER(*i_file.get(_dir_PKI_CA, _File_Name(d.FQDN+".key"))),
					CRL:  _DER(*i_file.get(_dir_PKI_CA, _File_Name(d.FQDN+".crl"))), // _DER(d.SKV[_skv_CRL][0]),
				},
				Node: __FQDN_PKI_Node{},
			}
			switch {
			case i_PKI_DB.CA_Node[d.FQDN].parse_DER(&x509.Certificate{
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
				// todo: LDAP Result Code 17 "Undefined Attribute Type": cACertificate: requires ;binary transfer .... what????
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN+".crt"), "", i_PKI_DB.CA_Node[d.FQDN].DER.Cert)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN+".key"), "", i_PKI_DB.CA_Node[d.FQDN].DER.Key)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN+".crl"), "", i_PKI_DB.CA_Node[d.FQDN].DER.CRL)
				d.replace(_skv_CA, []string{i_PKI_DB.CA_Node[d.FQDN].DER.Cert.String()})
				d.replace(_skv_CRL, []string{i_PKI_DB.CA_Node[d.FQDN].DER.CRL.String()})
			}
			d.PKI = i_PKI_DB.CA_Node[d.FQDN]
			i_PKI.put(i_PKI_DB.CA_Node[d.FQDN])
			d.replace(_skv_CA, []string{i_PKI_DB.CA_Node[d.FQDN].DER.Cert.String()})
			d.replace(_skv_CRL, []string{i_PKI_DB.CA_Node[d.FQDN].DER.CRL.String()})

			for _, f := range d.Raw_User.Entries {
				var (
					f_SKV, v_SKV = get_LDAP_SKV(f, map[string]int{b.User_CN: 1, _skv_entryDN: 1, _skv_gidNumber: 1, _skv_uidNumber: 1, _skv_SSH_PK: 0, _skv_P12: int(_UIx_IPx), _skv_labeledURI: 0, _skv_ipHostNumber: 1})
				)
				var (
					v_U = &i_LDAP_Domain_User{
						LDAP:       b,
						DN:         _DN(v_SKV[_skv_entryDN].get_first()),
						Domain:     d,
						Entry:      f,
						FQDN:       "",
						GID_List:   __GN_LDAP_Domain_Group{},
						GID_Number: _GID_Number(string_uint64(v_SKV[_skv_gidNumber].get_first())),
						IPPrefix:   netip.Prefix{},
						Modify:     nil,
						SKV:        v_SKV,
						UID:        _UID(v_SKV[b.User_CN].get_first()),
						UID_Number: _UID_Number(string_uint64(v_SKV[_skv_uidNumber].get_first())),
						PKI:        nil,
					}
				)
				switch {
				case v_U.UID_Number == 0:
					log.Errorf("LDAP DB '%v' inconsistent! UID '%v': UID_Number is '%v'; ACTION: report.", a.String(), v_U.DN, v_U.GID_Number)
					status = true
					fallthrough
				case v_U.GID_Number == 0:
					log.Warnf("LDAP DB '%v' inconsistent! primary GID_Number is not defined for UID '%v'; ACTION: skip user.", a.String(), f.DN)
					continue
				}

				switch v_IPPrefix := parse_interface(netip.ParsePrefix(v_SKV[_skv_ipHostNumber].get_first())).(netip.Prefix); { // modification candidate -> user's ip space
				case v_IPPrefix.IsValid():
					switch value, flag := i_ui_ip[v_IPPrefix]; {
					case flag && value.User == nil: // ip found and free
						log.Debugf("UID '%v', '%v' '%v'.", v_U.DN, _skv_ipHostNumber, v_IPPrefix)
						v_U.IPPrefix = v_IPPrefix
						i_ui_ip[v_U.IPPrefix].User = v_U
					case flag && value.User != nil: // ip found but occupied, so need ip assigment
						log.Warnf("LDAP DB '%v' inconsistent! UID '%v', '%v' '%v' occupied by '%v'; ACTION: find new.", a.String(), v_U.DN, _skv_ipHostNumber, v_IPPrefix, value.User.DN)
					}
				default: // ip not found, so need ip assigment
					log.Debugf("LDAP '%v': UID '%v', '%v' not defined; ACTION: find new.", a.String(), v_U.DN, _skv_ipHostNumber)
				}

				v_U.PKI = make(__PKI_Node, _UIx_IPx, _UIx_IPx)
				v_U.FQDN = b._DN_FQDN(v_U.DN)

				d.User[v_U.UID_Number] = v_U
				b.M_CN_U[v_U.DN] = v_U

				status = status || f_SKV
			}
		}
	}

	for a, b := range i_ldap {
		for _, d := range b.Domain {
			for _, f := range d.Raw_Group.Entries {
				var (
					f_SKV, v_SKV = get_LDAP_SKV(f, map[string]int{_skv_entryDN: 1, _skv_gidNumber: 1, _skv_labeledURI: 0, _skv_member: 0, _skv_owner: 0, b.Group_CN: 1})
				)
				var (
					v_G = &i_LDAP_Domain_Group{
						LDAP:           b,
						DN:             _DN(v_SKV[_skv_entryDN].get_first()),
						Domain:         d,
						Entry:          f,
						FQDN:           "",
						GID:            _GID(v_SKV[b.Group_CN].get_first()),
						GID_List:       nil,
						GID_Number:     _GID_Number(string_uint64(v_SKV[_skv_gidNumber].get_first())),
						Modify:         nil,
						Owner_GID_List: nil,
						Owner_UID_List: nil,
						SKV:            v_SKV,
						UID_List:       nil,
						PKI:            nil,
					}
					v_UID_List       = make(__UN_LDAP_Domain_User)
					v_GID_List       = make(__GN_LDAP_Domain_Group) // todo
					v_Owner_UID_List = make(__UN_LDAP_Domain_User)
					v_Owner_GID_List = make(__GN_LDAP_Domain_Group) // todo
				)
				for _, h := range v_SKV[_skv_member] {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil:
						log.Errorf("LDAP DB inconsistent! can't find member UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						status = true
						continue
					}
					v_UID_List[u.UID_Number] = u
				}
				for _, h := range v_SKV[_skv_owner] {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil:
						log.Errorf("LDAP DB inconsistent! can't find owner UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						status = true
						continue
					}
					v_Owner_UID_List[u.UID_Number] = u
				}

				switch {
				case v_G.GID_Number == 0:
					log.Errorf("LDAP DB inconsistent! GID '%v': GID_Number is '%v'; ACTION: report.", v_G.DN, v_G.GID_Number)
					status = true
				}

				v_G.FQDN = b._DN_FQDN(v_G.DN)

				v_G.UID_List = v_UID_List
				v_G.GID_List = v_GID_List
				v_G.Owner_UID_List = v_Owner_UID_List
				v_G.Owner_GID_List = v_Owner_GID_List

				d.Group[v_G.GID_Number] = v_G
				b.M_CN_G[v_G.DN] = v_G
				for _, j := range d.Group[v_G.GID_Number].UID_List {
					j.GID_List[v_G.GID_Number] = v_G
				}
				status = status || f_SKV
			}
			for _, f := range d.User {
				switch {
				case f.GID_Number != 0 && d.Group[f.GID_Number] == nil:
					log.Errorf("LDAP DB inconsistent! can't find primary GID_Number '%v' for UID '%v'; ACTION: report.", f.GID_Number, f.DN)
					status = true
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
								f.replace(_skv_ipHostNumber, []string{y.String()})
								log.Infof("LDAP '%v': UID '%v', found new ipHostNumber '%v'; ACTION: report.", a.String(), f.DN, y)
								return y
							}
						}
						log.Fatalf("not enough user ip space")
						status = true
						return
					}()
				)
				f.IPPrefix = v_IPPrefix
			}
		}
	}

	for a, b := range i_ldap { // third pass, fill PKI with known data or generate new
		for _, d := range b.Domain {

			for _, f := range d.Group {
				switch {
				case len(f.GID) >= 3 && f.GID[3:] == "vpn":
				default:
					continue
				}
			}

			for _, f := range d.User {
				switch f.UID {
				case "lom":
				default:
					continue
				}

				for _, h := range f.SKV[_skv_P12] {
					var (
						v_P12 = _P12(h)
					)
					switch v_FQDN, flag := v_P12.get_FQDN(); {
					case flag:
						switch _, flag = i_PKI_DB.CA_Node[d.FQDN].Node[v_FQDN]; {
						case flag:
							log.Errorf("LDAP DB '%v': P12 for '%v' already defined; ACTION: report.", a.String(), v_FQDN)
							status = true
							continue
						}
						i_PKI_DB.CA_Node[d.FQDN].Node[v_FQDN] = &_PKI_Node{
							FQDN: v_FQDN,
							CA:   i_PKI_DB.CA_Node[d.FQDN],
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
						h = _FQDN(join_string(".", "x"+pad_string(strconv.FormatInt(int64(g), 16), 2), h))
					}
					switch _, flag := i_PKI_DB.CA_Node[d.FQDN].Node[h]; {
					case !flag:
						i_PKI_DB.CA_Node[d.FQDN].Node[h] = &_PKI_Node{FQDN: h, CA: i_PKI_DB.CA_Node[d.FQDN]}
					}
					switch {
					case i_PKI_DB.CA_Node[d.FQDN].Node[h].parse_P12(&x509.Certificate{
						SerialNumber: big.NewInt(time.Now().UnixMicro()),
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
					}):
						changed = true
					}
					i_PKI.put(i_PKI_DB.CA_Node[d.FQDN].Node[h])
					f.PKI[g] = i_PKI_DB.CA_Node[d.FQDN].Node[h]
				}
				switch {
				case changed:
					var (
						changes = make([]string, _UIx_IPx, _UIx_IPx)
					)
					for k := 0; k < int(_UIx_IPx); k++ {
						// changes[k] = base64.StdEncoding.EncodeToString(f.PKI[k].P12)
						changes[k] = f.PKI[k].P12.String()
						i_file.put(_dir_PKI_Cert, _File_Name(f.PKI[k].Cert.SerialNumber.String()), "", f.PKI[k].P12)
					}
					f.replace(_skv_P12, changes)
				}
			}
		}
	}
	switch {
	case status:
		return status
	}

	return !status
}

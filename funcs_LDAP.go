package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
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
func read_ldap() {
	for a, b := range i_ldap {
		func() {
			var (
				_ldap *ldap.Conn
				err   error
			)
			switch _ldap, err = ldap.DialURL(a.String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); {
			case err != nil:
				log.Errorf("LDAP '%v': connect error '%v'; ACTION: skip.", a.String(), err)
				_fatal()
				return
			}
			defer _ldap.Close()
			switch err = _ldap.Bind(b.Bind_DN.String(), b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v': bind error '%v'; ACTION: skip.", a.String(), err)
				_fatal()
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
				_fatal()
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

				switch _dn {
				case "dc=domain,dc=tld":
				default:
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
					_fatal()
					continue
				}

				var (
					_host_request = ldap.NewSearchRequest(
						_dn.String(),
						ldap.ScopeWholeSubtree,
						ldap.DerefAlways,
						0,
						0,
						false,
						b.Host_Filter,
						[]string{"*", "+"},
						nil,
					)
					_host_result *ldap.SearchResult
				)
				switch _host_result, err = _ldap.Search(_host_request); {
				case err != nil:
					log.Fatalf("LDAP '%v': search error '%v'; ACTION: fatal.", a.String(), err)
					_fatal()
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
					_fatal()
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
					_fatal()
					continue
				}

				i_ldap_domain[_dn] = &i_LDAP_Domain{
					DN:        _dn,
					Entry:     nil,
					FQDN:      "",
					Group:     __GN_LDAP_Domain_Group{},
					Host:      __DN_LDAP_Domain_Host{},
					LDAP:      b,
					Modify:    nil,
					PKI:       nil,
					Raw_DC:    _dc_result,
					Raw_Group: _group_result,
					Raw_Host:  _host_result,
					Raw_User:  _user_result,
					SKV:       nil,
					User:      __UN_LDAP_Domain_User{},
				}
				i_ldap[a].Domain[_dn] = i_ldap_domain[_dn]
			}
		}()
	}
}
func write_ldap() {
	_check()
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
							// 				_fatal()
						default:
							log.Infof("LDAP '%v': done modification for '%v'; ACTION: report.", a.String(), inbound.DN)
						}
					}
				}
				err error
			)
			switch _ldap, err = ldap.DialURL(a.String(), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})); {
			case err != nil:
				log.Errorf("LDAP '%v': connect error '%v'; ACTION: skip.", a.String(), err)
				_fatal()
				return
			}
			defer _ldap.Close()
			switch err = _ldap.Bind(b.Bind_DN.String(), b.Secret.String()); {
			case err != nil:
				log.Errorf("LDAP '%v': bind error '%v'; ACTION: skip.", a.String(), err)
				_fatal()
				return
			}

			for _, d := range b.Domain {
				do_modify(d.Modify)
				for _, f := range d.Host {
					do_modify(f.Modify)
				}
				for _, f := range d.Group {
					do_modify(f.Modify)
				}
				for _, f := range d.User {
					do_modify(f.Modify)
				}
			}
		}()
	}
}
func get_LDAP_SKV(inbound *ldap.Entry, list map[string]int) (outbound __S_LDAP_SKV) {
	outbound = make(__S_LDAP_SKV)
	for a, b := range list {
		var (
			attr = inbound.GetAttributeValues(a)
			flag = b != 0
		)
		outbound[a] = &i_LDAP_SKV{
			Value:   map[string]bool{},
			Ordered: []string{},
		}
		for _, d := range attr {
			switch {
			case len(d) == 0 || outbound[a].Value[d]:
				continue
			}
			outbound[a].Value[d] = true
			outbound[a].Ordered = append(outbound[a].Ordered, d)
		}
		sort.Slice(outbound[a].Ordered, func(i, j int) bool {
			return outbound[a].Ordered[i] < outbound[a].Ordered[j]
		})

		switch {
		case flag:
			switch {
			case len(outbound[a].Value) < b:
				log.Debugf("DN '%v': not enough '%v' defined in LDAP; ACTION: generate the rest.", inbound.DN, a)
				// outbound[a] = make([]string, b, b)
			case len(outbound[a].Value) == b:
				// outbound[a] = make([]string, b, b)
			case len(outbound[a].Value) > b:
				log.Errorf("DN '%v': too many '%v' defined in LDAP; ACTION: report.", inbound.DN, a)
				_fatal()
			}
		}

		switch {
		case a == _skv_labeledURI:
			for e := range outbound[a].Value {
				var (
					lattr = re_strict_splitters.Split(e, -1)
				)
				switch {
				case len(lattr) < 2:
					continue
				}
				outbound[lattr[0]] = &i_LDAP_SKV{
					Value:   map[string]bool{},
					Ordered: []string{},
				}

				for _, d := range lattr[1:] {
					outbound[lattr[0]].Value[d] = true
					outbound[lattr[0]].Ordered = append(outbound[lattr[0]].Ordered, d)
				}
				sort.Slice(outbound[lattr[0]].Ordered, func(i, j int) bool {
					return outbound[lattr[0]].Ordered[i] < outbound[lattr[0]].Ordered[j]
				})

			}
		}

	}

	return
}

func parse_LDAP() {
	for a, b := range i_ldap {
		for _, d := range b.Domain {
			d.FQDN = b._DN_FQDN(_re_point, d.DN)
			for _, f := range d.Raw_DC.Entries {
				d.SKV = get_LDAP_SKV(f, map[string]int{_skv_CA: 1, _skv_CRL: 1})
				d.Entry = f
			}

			switch _, flag := i_PKI_DB.CA_Node[d.FQDN]; {
			case flag:
				log.Errorf("PKI DB '%v' already defined; ACTION: report.", d.FQDN)
				_fatal()
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
				Host_Node: __FQDN_PKI_Host_Node{},
				Node:      __FQDN_PKI_Node{},
			}
			d.PKI = i_PKI_DB.CA_Node[d.FQDN]

			switch {
			case d.PKI.parse_DER(&x509.Certificate{
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
				// todo: LDAP Result Code 17 "Undefined Attribute Type":
				//  cACertificate: requires ;binary transfer .... what????
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN+".crt"), "", d.PKI.DER.Cert)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN+".key"), "", d.PKI.DER.Key)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN+".crl"), "", d.PKI.DER.CRL)
				d.replace(_skv_CA, []string{d.PKI.DER.Cert.String()})
				d.replace(_skv_CRL, []string{d.PKI.DER.CRL.String()})
			}
			i_PKI.put(d.PKI)
			d.replace(_skv_CA, []string{d.PKI.DER.Cert.String()})
			d.replace(_skv_CRL, []string{d.PKI.DER.CRL.String()})

			i_file.write()

			for _, f := range d.Raw_Host.Entries {
				var (
					v_SKV = get_LDAP_SKV(f, map[string]int{b.Host_CN: 1, _skv_entryDN: 1, _skv_SSH_PK: 0, _skv_P12: 0, _skv_labeledURI: 0})
					v_DN  = _DN(v_SKV[_skv_entryDN].get_first())
				)
				switch _, flag := i_host[v_DN]; {
				case flag:
					log.Errorf("LDAP DB '%v' Host '%v' already defined; ACTION: report.", d.FQDN, v_DN)
					_fatal()
					continue
				}
				var (
					v_H = &i_LDAP_Domain_Host{
						Address:    _FQDN(v_SKV[_lURI_openvpnd_address].get_first()),
						DN:         v_DN,
						Domain:     d,
						Entry:      f,
						FQDN:       b._DN_FQDN(_re_point, v_DN),
						IPPrefix:   parse_interface(netip.ParsePrefix(v_SKV[_lURI_openvpnd_ip].get_first())).(netip.Prefix),
						LDAP:       b,
						Modify:     nil,
						PKI:        nil,
						PName:      "",
						PPort:      "",
						Port:       _INet_Port(string_uint64(v_SKV[_lURI_openvpnd_port].get_first())),
						SKV:        v_SKV,
						SSH_Client: v_SKV[_skv_SSH_PK].get_all(),
						TLSv2:      nil,
						TLSv2_User: nil,
					}
				)
				v_H.PPort = _PName(pad_string(v_H.Port, 5))
				v_H.PName = _PName(join_string("", "ID", v_H.PPort))

				for _, h := range v_H.SKV[_skv_P12].get_all() {
					var (
						v_P12 = _P12(h)
					)
					v_P12.parse_Host_Node(d.PKI)
				}

				var (
					changed bool
				)
				for _, h := range []_FQDN{v_H.FQDN, v_H.Address} {
					switch _, flag := d.PKI.Host_Node[h]; {
					case !flag:
						d.PKI.Host_Node[h] = &_PKI_Host_Node{FQDN: h, CA: d.PKI}
					}
					switch {
					case d.PKI.Host_Node[h].parse_P12(&x509.Certificate{
						SerialNumber: big.NewInt(time.Now().UnixMicro()),
						Subject: pkix.Name{
							Organization: []string{d.FQDN.String()},
							CommonName:   h.String(),
							Names:        nil,
							ExtraNames:   nil,
						},
						NotBefore:      time.Now(),
						NotAfter:       time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
						IsCA:           false,
						ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
						KeyUsage:       x509.KeyUsageDigitalSignature,
						DNSNames:       []string{h.String()},
						EmailAddresses: []string{join_string("@", "ns", d.FQDN)},
					}):
						changed = true
						i_PKI.put(d.PKI.Host_Node[h])
					}

				}
				v_H.PKI = d.PKI.Host_Node[v_H.FQDN]
				switch {
				case changed:
					var (
						changes []string
					)
					for _, h := range []_FQDN{v_H.FQDN, v_H.Address} {
						changes = append(changes, d.PKI.Host_Node[h].P12.String())
						i_file.put(_dir_PKI_Cert, _File_Name(d.PKI.Host_Node[h].Cert.SerialNumber.String()), "", d.PKI.Host_Node[h].P12)
					}
					v_H.replace(_skv_P12, changes)
				}

				d.Host[v_H.DN] = v_H
				i_host[v_H.DN] = v_H

			}

			for _, f := range d.Raw_User.Entries {
				var (
					v_SKV = get_LDAP_SKV(f, map[string]int{b.User_CN: 1, _skv_entryDN: 1, _skv_gidNumber: 1, _skv_uidNumber: 1, _skv_SSH_PK: 0, _skv_P12: int(_UIx_IPx), _skv_labeledURI: 0, _skv_ipHostNumber: 1})
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
					_fatal()
					continue
				}
				switch {
				case v_U.GID_Number == 0:
					log.Warnf("LDAP DB '%v' inconsistent! primary GID_Number is not defined for UID '%v'; ACTION: skip user.", a.String(), f.DN)
					_fatal()
					continue
				}

				switch v_IPPrefix := parse_interface(netip.ParsePrefix(v_SKV[_skv_ipHostNumber].get_first())).(netip.Prefix); { // modification candidate -> user's ip space
				case v_IPPrefix.IsValid():
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
				v_U.FQDN = b._DN_FQDN(_re_dog, v_U.DN)

				for _, h := range v_U.SKV[_skv_P12].get_all() {
					var (
						v_P12 = _P12(h)
					)
					v_P12.parse_Node(d.PKI)
				}

				//

				d.User[v_U.UID_Number] = v_U
				b.M_CN_U[v_U.DN] = v_U

			}
		}
	}

	for a, b := range i_ldap {
		for _, d := range b.Domain {
			for _, f := range d.Raw_Group.Entries {
				var (
					v_SKV  = get_LDAP_SKV(f, map[string]int{_skv_entryDN: 1, _skv_gidNumber: 1, _skv_labeledURI: 0, _skv_member: 0, _skv_owner: 0, b.Group_CN: 1})
					v_DN   = _DN(v_SKV[_skv_entryDN].get_first())
					v_FQDN = b._DN_FQDN(_re_point, v_DN)
					// v_OVPNN = _FQDN(v_SKV[_lURI_openvpn].get_first())
					// v_OVPN  *i_LDAP_Domain_Host
					v_OVPN, _ = i_host[_DN(v_SKV[_lURI_openvpn].get_first())]
				)
				// switch v_OVPN, flag := d.Host[v_OVPNN]; {
				// case flag:
				//
				// }
				var (
					v_G = &i_LDAP_Domain_Group{
						DN:             v_DN,
						Domain:         d,
						Entry:          f,
						FQDN:           v_FQDN,
						GID:            _GID(v_SKV[b.Group_CN].get_first()),
						GID_List:       nil,
						GID_Number:     _GID_Number(string_uint64(v_SKV[_skv_gidNumber].get_first())),
						LDAP:           b,
						Modify:         nil,
						Owner_GID_List: nil,
						Owner_UID_List: nil,
						PKI:            nil,
						SKV:            v_SKV,
						UID_List:       nil,
						FW_v00:         nil,
						OVPN:           v_OVPN,
					}
					v_UID_List       = make(__UN_LDAP_Domain_User)
					v_GID_List       = make(__GN_LDAP_Domain_Group) // todo
					v_Owner_UID_List = make(__UN_LDAP_Domain_User)
					v_Owner_GID_List = make(__GN_LDAP_Domain_Group) // todo
				)
				for _, h := range v_SKV[_skv_member].get_all() {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil:
						log.Errorf("LDAP DB inconsistent! can't find member UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						_fatal()
						continue
					}
					v_UID_List[u.UID_Number] = u
				}
				for _, h := range v_SKV[_skv_owner].get_all() {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil:
						log.Errorf("LDAP DB inconsistent! can't find owner UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						_fatal()
						continue
					}
					v_Owner_UID_List[u.UID_Number] = u
				}

				switch {
				case v_G.GID_Number == 0:
					log.Errorf("LDAP DB inconsistent! GID '%v': GID_Number is '%v'; ACTION: report.", v_G.DN, v_G.GID_Number)
					_fatal()
				}

				v_G.UID_List = v_UID_List
				v_G.GID_List = v_GID_List
				v_G.Owner_UID_List = v_Owner_UID_List
				v_G.Owner_GID_List = v_Owner_GID_List

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
					_fatal()
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
						_fatal()
						return
					}()
				)
				f.IPPrefix = v_IPPrefix
			}
		}
	}

	for _, b := range i_ldap { // third pass, fill PKI with known data or generate new
		for _, d := range b.Domain {
			for _, f := range d.User {
				switch f.UID {
				case "lom":
				default:
					continue
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

	for _, b := range i_ldap { // third pass, fill PKI with known data or generate new
		for _, d := range b.Domain {
			for _, f := range d.Group {
				switch {
				case len(f.GID) >= 3 && f.GID[:3] == "vpn" && f.OVPN != nil:
				default:
					continue
				}
				// todo: gen this keys w/o external call
				switch {
				case f.OVPN.TLSv2 == nil:
					f.OVPN.TLSv2 = _PEM(*i_file.get(_dir_PKI_TLS, _File_Name(f.FQDN)))
				}
				switch {
				case len(f.OVPN.TLSv2) == 0:
					log.Warnf("TLSv2 server key for '%v' not found; ACTION: generate.", f.FQDN)
					i_file.put(_dir_PKI_TLS, _File_Name(f.FQDN), "", _file_openvpn.external("--genkey", "tls-crypt-v2-server"))
					f.OVPN.TLSv2 = _PEM(*i_file.get(_dir_PKI_TLS, _File_Name(f.FQDN)))
				}
				f.OVPN.TLSv2_User = make(map[_UID_Number][]_PEM)
				i_file.write()

				for _, x := range []_W{_W_tcp, _W_udp} {
					i_OVPN[f.FQDN] = &_OVPN_GT_Server{
						Address: f.OVPN.Address,
						ExternalIP: func() (outbound string) {
							switch value, err := net.LookupIP(f.OVPN.Address.String()); {
							case err != nil:
								log.Errorf("Error resolving '%v'; ACTION: report.", f.OVPN.Address)
								_fatal()
							default:
								outbound = interface_string("", value)
							}
							return
						}(),
						Port:       f.OVPN.Port,
						PName:      f.OVPN.PName,
						Proto:      _INet_Protocol(x),
						InternalIP: f.OVPN.IPPrefix.Addr().String(),
						Subnet:     _UIx_Addr,
						Netmask:    "255.240.0.0",
					}
					var (
						p_pki  = _dir_Stage_OVPN_ULE.a(_Dir_Name(f.OVPN.PName), "pki")
						f_conf = _File_Name(join_string(".", join_string("_", "openvpn", f.OVPN.PName, x), "conf"))
					)
					i_file.put(p_pki, "ca.crt.pem", "", d.PKI.PEM.Cert)
					i_file.put(p_pki, "server.crt.pem", "", f.OVPN.PKI.PEM.Cert)
					i_file.put(p_pki, "server.key.pem", "", f.OVPN.PKI.PEM.Key)
					i_file.put(p_pki, "server.dh.pem", "", f.OVPN.PKI.PEM.DH)
					i_file.put(p_pki, "crl.crl.pem", "", d.PKI.PEM.CRL)
					i_file.put(p_pki, "server.tls.key.pem", "", f.OVPN.TLSv2)
					i_file.put(_dir_Stage_OVPN_ULE, f_conf, "", i_file.get(_dir_GT_OVPN, "server").parse_GT(i_OVPN[f.FQDN]))
				}
				i_file.write()

				for g, h := range f.UID_List {
					switch h.UID {
					case "lom":
					default:
						continue
					}

					f.OVPN.TLSv2_User[g] = make([]_PEM, _UIx_IPx, _UIx_IPx)
					for i := range h.PKI {
						switch {
						case i < 1 || i > len(_re_lower_case):
							continue
						}
						var (
							tlsv2_fn = _File_Name(join_string("_", f.FQDN, h.FQDN))
						)
						f.OVPN.TLSv2_User[g][i] = _PEM(*i_file.get(_dir_PKI_TLS, tlsv2_fn))
						switch {
						case f.OVPN.TLSv2_User[g][i] == nil || len(f.OVPN.TLSv2_User[g][i]) == 0:
							log.Warnf("TLSv2 client key for '%v' not found; ACTION: generate.", tlsv2_fn)
							i_file.put(_dir_PKI_TLS, tlsv2_fn, "",
								_file_openvpn.external("--tls-crypt-v2", i_file.fn(_dir_PKI_TLS, _File_Name(f.FQDN)).String(), "--genkey", "tls-crypt-v2-client"))
							f.OVPN.TLSv2_User[g][i] = _PEM(*i_file.get(_dir_PKI_TLS, tlsv2_fn))
						}
						i_file.write()

						var (
							c_GT = &_OVPN_GT_Client{
								Address: f.OVPN.Address,
								CA:      d.PKI.PEM.Cert,
								Cert:    h.PKI[i].PEM.Cert,
								Key:     h.PKI[i].PEM.Key,
								Netmask: "255.240.0.0",
								Port:    f.OVPN.Port,
								Proto:   []_INet_Protocol{_INet_Protocol(_W_tcp), _INet_Protocol(_W_udp)},
								PName:   f.OVPN.PName,
								Subnet:  i_ui_ip[h.IPPrefix.Masked()].Conn[i].Addr().String(),
								TLSv2:   f.OVPN.TLSv2_User[g][i],
							}
							p_ccd            = _dir_Stage_OVPN_ULE.a(_Dir_Name(i_OVPN[f.FQDN].PName), "ccd")
							p_client_profile = _dir_Portal.a(_Dir_Name(d.FQDN), _Dir_Name(f.FQDN), _Dir_Name(h.FQDN))
						)
						i_file.put(p_ccd, _File_Name(h.PKI[i].FQDN), "", i_file.get(_dir_GT_OVPN, "client_ccd").parse_GT(c_GT))
						i_file.put(p_client_profile, _File_Name(join_string(".", h.PKI[i].FQDN, "ovpn")), "", i_file.get(_dir_GT_OVPN, "client_profile").parse_GT(c_GT))
					}
					i_file.write()

				}
				i_file.write()

			}

			i_file.put(_dir_Stage_OVPN_ULE, "client_connect.sh", "", i_file.get(_dir_GT_OVPN, "client_connect.sh").parse_GT(i_OVPN))
			i_file.put(_dir_Stage_OVPN_ULE, "client_disconnect.sh", "", i_file.get(_dir_GT_OVPN, "client_disconnect.sh").parse_GT(i_OVPN))
			i_file.e(_dir_Stage_OVPN_ULE, "client_connect.sh")
			i_file.e(_dir_Stage_OVPN_ULE, "client_disconnect.sh")
			i_file.put(_dir_Stage_OVPN_ULE, "server_cron", "", i_file.get(_dir_GT_OVPN, "server_cron").parse_GT(i_OVPN))
			i_file.put(_dir_Stage_OVPN_ULE, "server_Juniper", "", i_file.get(_dir_GT_OVPN, "server_Juniper").parse_GT(i_OVPN))
			i_file.write()

		}
	}
}

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func ldap_modify_Add_Attr(inbound *ldap.Entry, outbound *ldap.ModifyRequest, attrName string) {
	switch {
	case inbound == nil:
		log.Warnf("LDAP DB nothing to modify '%v' '%v' '%v'; ACTION: skip.", inbound, outbound.DN, attrName)
		return
	}
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
					b.DB_Filter,
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

				log.Infof("LDAP '%v' search result: '%v'.", a.String(), _dn)
				switch _, flag := i_ldap_domain[_dn]; {
				case flag:
					log.Warnf("LDAP '%v': domain already defined; ACTION: skip.", a)
					continue
				}

				var (
					_ca_request = ldap.NewSearchRequest(
						_dn.String(),
						ldap.ScopeWholeSubtree,
						ldap.DerefAlways,
						0,
						0,
						false,
						b.CA_Filer,
						[]string{"*", "+"},
						nil,
					)
					_ca_result *ldap.SearchResult
				)
				switch _ca_result, err = _ldap.Search(_ca_request); {
				case err != nil:
					log.Fatalf("LDAP '%v': search error '%v'; ACTION: fatal.", a.String(), err)
					_fatal()
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
					Raw_CA:    _ca_result,
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
				d.Modify = nil
				for _, f := range d.Host {
					do_modify(f.Modify)
					f.Modify = nil
				}
				for _, f := range d.Group {
					do_modify(f.Modify)
					f.Modify = nil
				}
				for _, f := range d.User {
					do_modify(f.Modify)
					f.Modify = nil
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
	i_file.check(_dir_Stage_OVPN_ULE_Cron, "")
	i_file.check(_dir_Stage_OVPN_ULE_RC_D, "")

	log.Debugf("Parsing start: LDAP; ACTION: report.")
	for a, b := range i_ldap {
		log.Debugf("Parsing start: LDAP '%v'; ACTION: report.", a.String())
		for _, d := range b.Domain {
			log.Debugf("Parsing start: LDAP Domain '%v'; ACTION: report.", d.DN)
			d.FQDN = b._DN_FQDN(_re_point, d.DN)

			log.Debugf("Parsing start: LDAP Raw_CA; ACTION: report.")
			for _, f := range d.Raw_CA.Entries {
				log.Debugf("Parsing start: LDAP Raw_CA '%v'; ACTION: report.", f.DN)
				var (
					v_SKV = get_LDAP_SKV(f, map[string]int{_skv_labeledURI: 0})
				)
				for _, h := range v_SKV[_lURI_revoke].Ordered {
					switch _, flag := i_PKI_Revoke[_FQDN(h)]; {
					case flag:
						log.Debugf("LDAP DB: FQDN for revocation already defined '%v'; ACTION: skip.", h)
					case !flag:
						i_PKI_Revoke[_FQDN(h)] = true
					}
				}
			}
			log.Debugf("Parsing done: LDAP Raw_CA; ACTION: report.")

			log.Debugf("Parsing start: LDAP Raw_DC; ACTION: report.")
			for _, f := range d.Raw_DC.Entries {
				log.Debugf("Parsing start: LDAP Raw_DC '%v'; ACTION: report.", f.DN)
				d.SKV = get_LDAP_SKV(f, map[string]int{_skv_CA: 1, _skv_CRL: 1})
				d.Entry = f
			}
			log.Debugf("Parsing done: LDAP Raw_DC; ACTION: report.")

			i_PKI.parse_Raw(
				_PKI_Raw(*i_file.get(_dir_PKI_CA, _File_Name(d.FQDN).a("crt", "pem"))),
				_PKI_Raw(*i_file.get(_dir_PKI_CA, _File_Name(d.FQDN).a("key", "pem"))),
				_PKI_Raw(*i_file.get(_dir_PKI_CA, _File_Name(d.FQDN).a("crl", "pem"))),
			)

			var (
				is_new bool
			)
			d.PKI, is_new = i_PKI.verify(nil, d.FQDN, &x509.Certificate{
				SignatureAlgorithm: x509.ECDSAWithSHA512,
				// SignatureAlgorithm: x509.PureEd25519,
				SerialNumber: pki_crt_sn(),
				Subject: pkix.Name{
					Organization: []string{d.FQDN.String()},
					CommonName:   d.FQDN.String(),
					Names:        nil,
					ExtraNames:   nil,
				},
				NotBefore:             time.Now(),
				NotAfter:              pki_crt_expiry(),
				IsCA:                  true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
				BasicConstraintsValid: true,
				CRLDistributionPoints: []string{join_string("", "http://", join_string(".", "ns", d.FQDN), "/crl.pem")},
				DNSNames:              []string{d.FQDN.String()},
				EmailAddresses:        []string{join_string("@", "ns", d.FQDN)},
				IPAddresses:           nil,
			})

			switch {
			case is_new:
				// todo: LDAP Result Code 17 "Undefined Attribute Type":
				//  cACertificate: requires ;binary transfer .... what????
				// i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("crt", "der"), "", d.PKI.DER.Cert)
				// i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("key", "der"), "", d.PKI.DER.Key)
				// i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("crl", "der"), "", d.PKI.DER.CRL)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("crt", "pem"), "", d.PKI.PEM.Cert)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("key", "pem"), "", d.PKI.PEM.Key)
				i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("crl", "pem"), "", d.PKI.PEM.CRL)
				i_file.put(_dir_PKI_Cert.a(d.FQDN), _File_Name(d.FQDN).a("crt", "pem"), "", d.PKI.PEM.Cert)
				d.replace(_skv_CA, []string{d.PKI.PEM.Cert.String()})
				d.replace(_skv_CRL, []string{d.PKI.PEM.CRL.String()})
			}
			// d.replace(_skv_CA, []string{d.PKI.DER.Cert.String()})
			// d.replace(_skv_CRL, []string{d.PKI.DER.CRL.String()})

			// i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("crt", "pem"), "", d.PKI.PEM.Cert)
			// i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("key", "pem"), "", d.PKI.PEM.Key)
			// i_file.put(_dir_PKI_CA, _File_Name(d.FQDN).a("crl", "pem"), "", d.PKI.PEM.CRL)

			i_file.put(_dir_PKI_Cert.a(d.FQDN), _File_Name(d.FQDN).a("crt", "pem"), "", d.PKI.PEM.Cert)

			i_file.write()
			write_ldap()

			log.Debugf("Parsing start: LDAP Raw_Host; ACTION: report.")
			for _, f := range d.Raw_Host.Entries {
				log.Debugf("Parsing start: LDAP Raw_Host '%v'; ACTION: report.", f.DN)
				is_new = false
				var (
					v_SKV = get_LDAP_SKV(f, map[string]int{_skv_uid: 1, b.Host_CN: 1, _skv_entryDN: 1, _skv_SSH_PK: 0, _skv_P12: 0, _skv_labeledURI: 0})
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
					i_PKI.parse_Raw(_PKI_Raw(h))
				}

				var (
					changed bool
					changes []string
				)
				for _, h := range []_FQDN{v_H.FQDN, v_H.Address} {
					var (
						v_CommonName string
						v_FQDN       _FQDN
						v_DNSNames   []string
					)
					switch h {
					case d.FQDN, "":
						continue
					case _FQDN(join_string(".", "_", d.FQDN)):
						v_CommonName = join_string(".", "*", d.FQDN)
						v_FQDN = _FQDN(v_CommonName)
						v_DNSNames = []string{d.FQDN.String(), v_CommonName}
					default:
						v_CommonName = h.String()
						v_FQDN = h
						v_DNSNames = []string{v_CommonName}
					}

					v_H.PKI, changed = i_PKI.verify(d.PKI, v_FQDN, &x509.Certificate{
						SignatureAlgorithm: x509.ECDSAWithSHA512,
						// SignatureAlgorithm: x509.PureEd25519,
						SerialNumber: pki_crt_sn(),
						Subject: pkix.Name{
							Organization: []string{d.FQDN.String()},
							CommonName:   v_CommonName,
							Names:        nil,
							ExtraNames:   nil,
						},
						NotBefore:      time.Now(),
						NotAfter:       pki_crt_expiry(),
						IsCA:           false,
						ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
						KeyUsage:       x509.KeyUsageDigitalSignature,
						DNSNames:       v_DNSNames,
						EmailAddresses: []string{join_string("@", "ns", d.FQDN)},
					})
					is_new = is_new || changed
					changes = append(changes, v_H.PKI.PEM.bundle().String())
				}
				switch {
				case is_new:
					v_H.replace(_skv_P12, changes)
				}

				i_file.put(_dir_PKI_Cert.a(d.FQDN), _File_Name(v_H.FQDN).a("crt", "pem"), "", v_H.PKI.PEM.Cert)
				i_file.put(_dir_PKI_Cert.a(d.FQDN), _File_Name(v_H.FQDN).a("key", "pem"), "", v_H.PKI.PEM.Key)

				d.Host[v_H.DN] = v_H
				i_host[v_H.DN] = v_H
			}
			i_file.write()
			write_ldap()
			log.Debugf("Parsing done: LDAP Raw_Host; ACTION: report.")

			log.Debugf("Parsing start: LDAP Raw_User; ACTION: report.")
			for _, f := range d.Raw_User.Entries {
				log.Debugf("Parsing start: LDAP Raw_User '%v'; ACTION: report.", f.DN)
				is_new = false
				var (
					v_SKV = get_LDAP_SKV(f, map[string]int{_skv_uid: 1, b.User_CN: 1, _skv_entryDN: 1, _skv_gidNumber: 1, _skv_uidNumber: 1, _skv_SSH_PK: 0, _skv_P12: int(_UIx_IPx), _skv_labeledURI: 0, _skv_ipHostNumber: 1})
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
					log.Warnf("LDAP DB '%v' inconsistent! UID '%v': UID_Number is '%v'; ACTION: skip user.", a.String(), v_U.DN, v_U.UID_Number)
					// _fatal()
					continue
				}
				switch {
				case v_U.GID_Number == 0:
					log.Warnf("LDAP DB '%v' inconsistent! UID '%v': primary GID_Number is '%v'; ACTION: skip user.", a.String(), v_U.DN, v_U.GID_Number)
					// _fatal()
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

				v_U.PKI = make(__PKI_Container, _UIx_IPx, _UIx_IPx)
				v_U.FQDN = b._DN_FQDN(_re_dog, v_U.DN)

				for _, h := range v_U.SKV[_skv_P12].get_all() {
					i_PKI.parse_Raw(_PKI_Raw(h))
				}

				log.Debugf("Parsing start: LDAP User Conn; ACTION: report.")
				for g := 0; g < int(_UIx_IPx); g++ {
					var (
						h       = v_U.FQDN
						changed bool
					)
					switch {
					case g >= 1 && g <= len(_re_lower_case):
						h = _FQDN(join_string(".", string(rune(g+96)), h))
					case g > len(_re_lower_case):
						h = _FQDN(join_string(".", "x"+pad_string(strconv.FormatInt(int64(g), 16), 2), h))
					}
					v_U.PKI[g], changed = i_PKI.verify(d.PKI, h, &x509.Certificate{
						SignatureAlgorithm: x509.ECDSAWithSHA512,
						// SignatureAlgorithm: x509.PureEd25519,
						SerialNumber: pki_crt_sn(),
						Subject: pkix.Name{
							Organization: []string{d.FQDN.String()},
							CommonName:   h.String(),
							Names:        nil,
							ExtraNames:   nil,
						},
						NotBefore:      time.Now(),
						NotAfter:       pki_crt_expiry(),
						IsCA:           false,
						ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
						KeyUsage:       x509.KeyUsageDigitalSignature,
						EmailAddresses: []string{h.String()},
						// DNSNames:       []string{h.String()},
						// EmailAddresses: []string{join_string("@", "ns", d.FQDN)},
						// DNSNames:       []string{i.String()},
						// IPAddresses:    nil,
					})
					is_new = is_new || changed
				}
				log.Debugf("Parsing done: LDAP User Conn; ACTION: report.")

				switch {
				case is_new:
					var (
						changes = make([]string, _UIx_IPx, _UIx_IPx)
					)
					for k := 0; k < int(_UIx_IPx); k++ {
						changes[k] = v_U.PKI[k].PEM.bundle().String()
						i_file.put(_dir_PKI_Cert.a(d.FQDN, v_U.FQDN), _File_Name(v_U.PKI[k].FQDN).a("crt", "pem"), "", v_U.PKI[k].PEM.Cert)
						i_file.put(_dir_PKI_Cert.a(d.FQDN, v_U.FQDN), _File_Name(v_U.PKI[k].FQDN).a("key", "pem"), "", v_U.PKI[k].PEM.Key)
					}
					v_U.replace(_skv_P12, changes)
				}

				d.User[v_U.UID_Number] = v_U
				b.M_CN_U[v_U.DN] = v_U
				i_file.write()
				write_ldap()
			}
			log.Debugf("Parsing done: LDAP Raw_User; ACTION: report.")
		}
	}
	log.Debugf("Parsing done: LDAP; ACTION: report.")

	log.Debugf("Parsing start: LDAP; ACTION: report.")
	for a, b := range i_ldap {
		log.Debugf("Parsing start: LDAP '%v'; ACTION: report.", a.String())

		for _, d := range b.Domain {
			log.Debugf("Parsing start: LDAP Domain '%v'; ACTION: report.", d.DN)

			log.Debugf("Parsing start: LDAP Raw_Group; ACTION: report.")
			for _, f := range d.Raw_Group.Entries {
				log.Debugf("Parsing start: LDAP Raw_Group '%v'; ACTION: report.", f.DN)
				var (
					v_SKV     = get_LDAP_SKV(f, map[string]int{_skv_entryDN: 1, _skv_gidNumber: 1, _skv_labeledURI: 0, _skv_member: 0, _skv_owner: 0, b.Group_CN: 1})
					v_DN      = _DN(v_SKV[_skv_entryDN].get_first())
					v_FQDN    = b._DN_FQDN(_re_point, v_DN)
					v_OVPN, _ = i_host[_DN(v_SKV[_lURI_openvpn].get_first())]
					v_G       = &i_LDAP_Domain_Group{
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
					case u == nil: // todo
						log.Debugf("LDAP DB inconsistent! can't find member UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						// _fatal()
						continue
					}
					v_UID_List[u.UID_Number] = u
				}
				for _, h := range v_SKV[_skv_owner].get_all() {
					var (
						u = b.M_CN_U[_DN(h)]
					)
					switch {
					case u == nil: // todo
						log.Debugf("LDAP DB inconsistent! can't find owner UID '%v' of GID '%v'; ACTION: report.", h, v_G.DN)
						// _fatal()
						continue
					}
					v_Owner_UID_List[u.UID_Number] = u
				}

				switch {
				case v_G.GID_Number == 0:
					log.Errorf("LDAP DB inconsistent! GID '%v': GID_Number is '%v'; ACTION: report.", v_G.DN, v_G.GID_Number)
					// _fatal()
					continue
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
			log.Debugf("Parsing done: LDAP Raw_Group; ACTION: report.")

			log.Debugf("Parsing start: LDAP User; ACTION: report.")
			for _, f := range d.User {
				log.Debugf("Parsing start: LDAP User '%v'; ACTION: report.", f.DN)
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
			log.Debugf("Parsing done: LDAP User; ACTION: report.")
		}
	}

	log.Debugf("Parsing start: LDAP; ACTION: report.")
	for a, b := range i_ldap { // third pass, fill PKI with known data or generate new
		log.Debugf("Parsing start: LDAP '%v'; ACTION: report.", a.String())

		log.Debugf("Parsing start: LDAP Domain; ACTION: report.")
		for _, d := range b.Domain {
			log.Debugf("Parsing start: LDAP Domain '%v'; ACTION: report.", d.DN)

			// log.Debugf("Parsing start: LDAP User; ACTION: report.")
			// for _, f := range d.User {
			// 	log.Debugf("Parsing start: LDAP User '%v'; ACTION: report.", f.DN)
			// 	var (
			// 		p_client_profile = _dir_Portal.a(_Dir_Name(d.FQDN), ".user", _Dir_Name(f.FQDN))
			// 	)
			//
			// 	i_file.put(p_client_profile, _File_Name(h.PKI[i].FQDN), "ovpn", "", i_file.get(_dir_GT_OVPN, "client_profile", "tmpl").parse_GT(c_GT))
			// }
			// log.Debugf("Parsing done: LDAP User; ACTION: report.")

			log.Debugf("Parsing start: LDAP Group; ACTION: report.")
			for _, f := range d.Group {
				log.Debugf("Parsing start: LDAP Group '%v'; ACTION: report.", f.DN)
				switch {
				case len(f.GID) >= 3 && f.GID[:3] == "vpn" && f.OVPN != nil:
				default:
					continue
				}
				// todo: gen this keys w/o external call
				var (
					p_tls = _dir_PKI_TLS.a(d.FQDN)
				)
				i_file.read_file(p_tls, _File_Name(f.FQDN).a("tls", "pem"))
				f.OVPN.TLSv2 = _PEM_TLS_Server(*i_file.get(p_tls, _File_Name(f.FQDN).a("tls", "pem")))
				switch {
				case f.OVPN.TLSv2 == nil || len(f.OVPN.TLSv2) == 0:
					log.Warnf("TLSv2 server key for '%v' not found; ACTION: generate.", f.FQDN)
					i_file.put(p_tls, _File_Name(f.FQDN).a("tls", "pem"), "", _file_openvpn.external("--genkey", "tls-crypt-v2-server"))
					i_file.write()

					f.OVPN.TLSv2 = _PEM_TLS_Server(*i_file.get(p_tls, _File_Name(f.FQDN).a("tls", "pem")))
				}
				f.OVPN.TLSv2_User = make(map[_UID_Number][]_PEM_TLS_Client)

				log.Debugf("Parsing start: LDAP Proto; ACTION: report.")
				for _, x := range []_W{_W_tcp, _W_udp} {
					i_OVPN[f.FQDN] = &_OVPN_GT_Server{
						Address:    f.OVPN.Address,
						ExternalIP: f.OVPN.Address.resolve(),
						Port:       f.OVPN.Port,
						PName:      f.OVPN.PName,
						Proto:      _INet_Protocol(x),
						InternalIP: f.OVPN.IPPrefix.Addr(),
						Subnet:     _UIx_Addr,
						Netmask:    "255.240.0.0",
					}
					var (
						p_pki  = _dir_Stage_OVPN_ULE_OVPN.a(f.OVPN.PName, "pki")
						f_conf = _File_Name("openvpn").aa("_", f.OVPN.PName, x)
					)
					i_file.put(p_pki, "ca.crt.pem", "", d.PKI.PEM.Cert)
					i_file.put(p_pki, "server.crt.pem", "", i_PKI.FQDN[i_OVPN[f.FQDN].Address].PEM.Cert)
					i_file.put(p_pki, "server.key.pem", "", i_PKI.FQDN[i_OVPN[f.FQDN].Address].PEM.Key)
					i_file.put(p_pki, "ca.crl.pem", "", d.PKI.PEM.CRL)
					i_file.put(p_pki, "server.tls.key.pem", "", f.OVPN.TLSv2)
					i_file.put(_dir_Stage_OVPN_ULE_OVPN, f_conf.a("conf"), "", i_file.get(_dir_GT_OVPN, "server.tmpl").parse_GT(i_OVPN[f.FQDN]))
					i_file_link.l("openvpn", _Link_Name(_dir_Stage_OVPN_ULE_RC_D.a(f_conf)))

				}
				log.Debugf("Parsing done: LDAP Proto; ACTION: report.")

				log.Debugf("Parsing start: LDAP UID_List; ACTION: report.")
				for g, h := range f.UID_List {
					log.Debugf("Parsing start: LDAP UID_List '%v'; ACTION: report.", h.DN)
					f.OVPN.TLSv2_User[g] = make([]_PEM_TLS_Client, _UIx_IPx, _UIx_IPx)
					for i := range h.PKI {
						switch {
						case i < 1 || i > len(_re_lower_case):
							continue
						}
						var (
							p_tlsc = p_tls.a(f.FQDN)
						)
						i_file.read_file(p_tlsc, _File_Name(h.FQDN).a("tls", "pem"))
						f.OVPN.TLSv2_User[g][i] = _PEM_TLS_Client(*i_file.get(p_tlsc, _File_Name(h.FQDN).a("tls", "pem")))
						switch {
						case f.OVPN.TLSv2_User[g][i] == nil || len(f.OVPN.TLSv2_User[g][i]) == 0:
							log.Warnf("TLSv2 client key for '%v'/'%v' not found; ACTION: generate.", f.FQDN, h.FQDN)
							i_file.put(p_tlsc, _File_Name(h.FQDN).a("tls", "pem"), "",
								_file_openvpn.external("--tls-crypt-v2", i_file.fn(p_tls, _File_Name(f.FQDN).a("tls", "pem")).String(),
									"--genkey", "tls-crypt-v2-client"))
							i_file.write()

							f.OVPN.TLSv2_User[g][i] = _PEM_TLS_Client(*i_file.get(p_tlsc, _File_Name(h.FQDN).a("tls", "pem")))
						}

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
							p_ccd            = _dir_Stage_OVPN_ULE_OVPN.a(_Dir_Name(i_OVPN[f.FQDN].PName), "ccd")
							p_client_profile = _dir_Portal.a(_Dir_Name(d.FQDN), ".group", _Dir_Name(f.FQDN), _Dir_Name(h.FQDN))
						)
						i_file.put(p_ccd, _File_Name(h.PKI[i].FQDN), "", i_file.get(_dir_GT_OVPN, "client_ccd.tmpl").parse_GT(c_GT))
						i_file.put(p_client_profile, _File_Name(h.PKI[i].FQDN).a("ovpn"), "", i_file.get(_dir_GT_OVPN, "client_profile.tmpl").parse_GT(c_GT))

					}

				}
				log.Debugf("Parsing done: LDAP UID_List; ACTION: report.")

				log.Debugf("Parsing start: LDAP Owner_UID_List; ACTION: report.")
				for _, h := range f.Owner_UID_List {
					log.Debugf("Parsing start: LDAP Owner_UID_List '%v'; ACTION: report.", h.DN)
					var (
						p_source      = _Dir_Name("..").a("..", ".group", _Dir_Name(f.FQDN))
						p_destination = _dir_Portal.a(_Dir_Name(d.FQDN), ".owner", _Dir_Name(h.FQDN))
					)
					i_file.check(p_destination, "")
					i_file_link.l(_Link_Name(p_source), _Link_Name(p_destination.a(f.FQDN)))

				}
				log.Debugf("Parsing done: LDAP Owner_UID_List; ACTION: report.")

			}
			log.Debugf("Parsing done: LDAP Group; ACTION: report.")

			i_file.put(_dir_Stage_OVPN_ULE_OVPN, "client_connect.sh", "", i_file.get(_dir_GT_OVPN, "client_connect.tmpl").parse_GT(i_OVPN))
			i_file.put(_dir_Stage_OVPN_ULE_OVPN, "client_disconnect.sh", "", i_file.get(_dir_GT_OVPN, "client_disconnect.tmpl").parse_GT(i_OVPN))
			i_file.e(_dir_Stage_OVPN_ULE_OVPN, "client_connect.sh")
			i_file.e(_dir_Stage_OVPN_ULE_OVPN, "client_disconnect.sh")
			i_file.put(_dir_Stage_OVPN_ULE_OVPN, "cron.conf", "", i_file.get(_dir_GT_OVPN, "server_cron.tmpl").parse_GT(i_OVPN))
			i_file.put(_dir_Stage_OVPN_ULE_OVPN, "juniper.conf", "", i_file.get(_dir_GT_OVPN, "server_Juniper.tmpl").parse_GT(i_OVPN))
			i_file_link.l("../openvpn/cron.conf", _Link_Name(_dir_Stage_OVPN_ULE_Cron.a("openvpn")))

		}
		log.Debugf("Parsing done: LDAP Domain; ACTION: report.")

	}
	log.Debugf("Parsing done: LDAP; ACTION: report.")

}

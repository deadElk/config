package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"reflect"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

func (receiver *i_Peer) link_AB(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ab[value] == nil:
			continue
		}
		receiver.AB[value] = i_ab[value]
	}
}
func (receiver *i_Peer) link_JA(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ja[value] == nil:
			continue
		}
		receiver.JA[value] = i_ja[value]
	}
}
func (receiver *i_Peer) link_PL(name ..._Name) {
	for _, value := range name {
		switch {
		case i_pl[value] == nil:
			continue
		}
		receiver.PL[value] = i_pl[value]
	}
}
func (receiver *i_Peer) link_PS(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ps[value] == nil:
			continue
		}
		receiver.PS[value] = i_ps[value]
	}
}
func (receiver *i_Peer) create_AB_Set(name ..._Name) {
	for _, value := range name {
		create_iDB_AB_Set(value)
		receiver.link_AB(value)
	}
}

func (receiver *i_AB) get_address_list(interim *[]_Name) (outbound *[]_Name) {
	switch receiver.Type {
	case _Type_fqdn:
		return &[]_Name{0: _Name(receiver.FQDN)}
	case _Type_ipprefix:
		return &[]_Name{0: _Name(receiver.IPPrefix.String())}
	case _Type_set:
		var (
			t []_Name
		)
		for b := range receiver.Set {
			var (
				i = i_ab[b].get_address_list(interim)
			)
			for _, d := range *i {
				t = append(t, d)
			}
		}
		return &t
	}
	return
}
func (receiver __N_AB) parse_recurse_AB(inbound _Name) {
	receiver[inbound] = i_ab[inbound]
	for a, b := range i_ab[inbound].Set {
		switch {
		case b.Type != _Type_set || receiver[a] == nil:
			receiver.parse_recurse_AB(a)
		}
	}
}

// PKI CA Node
func (receiver *_PKI_CA_Node) parse_DER( /*inbound *_PKI_CA_Node_DER,*/ skel *x509.Certificate) { // parse/create a new CA Node
	switch {
	case receiver.DER == nil || len(receiver.DER.Cert) == 0 || len(receiver.DER.Key) == 0:
		log.Infof("no CA DER data; ACTION: generate a new CA Cert")
		receiver.generate(skel)
		return
	}

	var (
		err error
		t   = &_PKI_CA_Node{
			DER: &_PKI_CA_Node_DER{
				Cert: receiver.DER.Cert,
				Key:  receiver.DER.Key,
				CRL:  receiver.DER.CRL,
			},
		}
	)

	switch t.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Warnf("can't parse CA Cert - '%v'; ACTION: generate a new CA Cert", err)
		receiver.generate(skel)
		return
	}

	switch t.Key, err = x509.ParseECPrivateKey(receiver.DER.Key); {
	case err != nil:
		log.Warnf("can't parse CA Key - '%v'; ACTION: generate a new CA Cert", err)
		receiver.generate(skel)
		return
	}

	switch {
	case t.Cert.PublicKey == t.Key.Public():
		log.Warnf("CA Cert's signature doesn't match with CA Key's signature - '%v'; ACTION: generate a new CA Cert", err)
		receiver.generate(skel)
		return
	}

	switch {
	case receiver.CA != nil: // CA is intermediate
		switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
		case err != nil:
			log.Warnf("CA's signature doesn't match with parent CA signature - '%v'; ACTION: generate a new CA Cert", err)
			receiver.generate(skel)
			return
		}
	}

	switch t.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err != nil:
		log.Warnf("can't parse CA CRL - '%v'; ACTION: generate a new CA Cert", err)
		t.generate_CRL()
		fallthrough
	case t.Cert.CheckCRLSignature(t.CRL) != nil:
		log.Warnf("CRL's signature doesn't match with CA's signature - '%v'; ACTION: generate a new CRL", err)
		t.generate_CRL()
		// default:
		// 	t.DER.CRL = receiver.DER.CRL
	}

	receiver.Cert = t.Cert
	receiver.Key = t.Key
	receiver.CRL = t.CRL
	// receiver.DER.Cert = inbound.Cert
	// receiver.DER.Key = inbound.Key
	receiver.DER.CRL = t.DER.CRL
	switch {
	case i_PKI_SN.Cmp(receiver.Cert.SerialNumber) == -1:
		i_PKI_SN = receiver.Cert.SerialNumber
	}
}
func (receiver *_PKI_CA_Node) generate(inbound *x509.Certificate) { // generate cert for a CA Node
	switch {
	case inbound == nil:
		log.Infof("no CA Cert data; ACTION: ignore")
		return
	}
	var (
		err error
	)
	log.Infof("generating a new CA Cert")

	receiver.DER = &_PKI_CA_Node_DER{
		Cert: _DER{},
		Key:  _DER{},
		CRL:  _DER{},
	}

	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("can't generate a new CA Key - %v", err)
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new CA Key - %v", err)
	}

	var (
		ca_cert = inbound
		ca_key  = receiver.Key
	)
	switch {
	case receiver.CA != nil:
		ca_cert = receiver.CA.Cert
		ca_key = receiver.CA.Key
	}

	inc_big_Int(i_PKI_SN)
	inbound.SerialNumber = i_PKI_SN
	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, ca_cert, receiver.Key.Public(), ca_key); {
	case err != nil:
		log.Fatalf("can't create a new CA Cert - %v", err)
	}

	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Fatalf("can't parse a new CA Cert - %v", err)
	}

	// receiver.FQDN = _FQDN(receiver.Cert.Subject.String())
	i_file.put(_dir_PKI, _File_Name(receiver.FQDN), "", receiver.DER.Key)

	receiver.generate_CRL()
}
func (receiver *_PKI_CA_Node) generate_CRL() {
	var (
		err error
	)
	inc_big_Int(i_PKI_SN)
	switch receiver.DER.CRL, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  x509.ECDSAWithSHA512,
		RevokedCertificates: nil,
		Number:              i_PKI_SN,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions:     nil,
	}, receiver.Cert, receiver.Key); {
	case err != nil:
		log.Fatalf("can't create a new CA CRL - %v", err)
	}
	switch receiver.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err != nil:
		log.Fatalf("can't parse a new CA CRL - %v", err)
	}
}

// PKI Node
// func (receiver *_PKI_Node) parse_DER(inbound *_PKI_Node_DER, skel *x509.Certificate) { // parse/create a new Node
// 	switch {
// 	case len(inbound.Cert) == 0 && len(inbound.Key) == 0:
// 		log.Warnf("no DER data; ACTION: generate a new Cert")
// 		receiver.generate(skel)
// 		return
// 	}
//
// 	var (
// 		err error
// 		t   = &_PKI_Node{}
// 	)
//
// 	switch t.Cert, err = x509.ParseCertificate(inbound.Cert); {
// 	case err != nil:
// 		log.Warnf("can't parse Cert - '%v'; ACTION: generate a new Cert", err)
// 		receiver.generate(skel)
// 		return
// 	}
//
// 	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
// 	case err != nil:
// 		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
// 		receiver.generate(skel)
// 		return
// 	}
//
// 	switch t.Key, err = x509.ParseECPrivateKey(inbound.Key); {
// 	case err != nil:
// 		log.Warnf("can't parse Key - '%v'; ACTION: generate a new Cert", err)
// 		receiver.generate(skel)
// 		return
// 	}
//
// 	switch {
// 	case t.Cert.PublicKey == t.Key.Public():
// 		log.Warnf("Cert's signature doesn't match with Key's signature - '%v'; ACTION: generate a new CA Cert", err)
// 		receiver.generate(skel)
// 		return
// 	}
//
// 	switch t.P12, err = pkcs12.Encode(rand.Reader, t.Key, t.Cert, receiver.CA.CA_Chain, ""); {
// 	case err != nil:
// 		log.Warnf("can't encode P12 - '%v'; ACTION: generate a new Cert", err)
// 		receiver.generate(skel)
// 		return
// 	}
//
// 	receiver.Cert = t.Cert
// 	receiver.Key = t.Key
// 	receiver.DER = inbound
// 	receiver.P12 = t.P12
// 	switch {
// 	case i_PKI_SN.Cmp(receiver.Cert.SerialNumber) == -1:
// 		i_PKI_SN = receiver.Cert.SerialNumber
// 	}
//
// }

func (receiver *_PKI_Node) parse_P12( /*inbound _P12,*/ skel *x509.Certificate) { // parse P12 of a Node
	switch {
	case receiver.P12 == nil || len(receiver.P12) == 0:
		log.Warnf("no P12 data; ACTION: generate a new Cert")
		receiver.generate(skel)
		return
	}

	var (
		err      error
		key      interface{}
		ca_chain __Cert_Chain
		t        = &_PKI_Node{DER: &_PKI_Node_DER{}}
	)

	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, ""); {
	case err != nil:
		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
		fallthrough
	case len(ca_chain) != len(receiver.CA.CA_Chain):
		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
		fallthrough
	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
		log.Warnf("unsupported key type; ACTION: generate a new Cert")
		fallthrough
	case false:
		receiver.generate(skel)
		return
	}

	for a, b := range ca_chain {
		switch {
		case receiver.CA.CA_Chain[a] != b:
			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
			receiver.generate(skel)
			return
		}
	}

	switch t.Key = key.(*ecdsa.PrivateKey); {
	case convert_2_string("", t.Cert.PublicKey) != convert_2_string("", t.Key.Public()): // todo: dirty hack
		// case t.Cert.PublicKey != t.Key.Public(): // todo: WTF???? not equal even if equal????
		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
		receiver.generate(skel)
		return
	}

	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
	case err != nil:
		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
		receiver.generate(skel)
		return
	}

	// P12 valid
	// receiver.P12 = inbound

	receiver.Cert = t.Cert
	receiver.Key = t.Key

	receiver.DER = &_PKI_Node_DER{
		Cert: receiver.Cert.Raw,
		Key:  nil,
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new Key - %v", err)
	}

	switch {
	case i_PKI_SN.Cmp(receiver.Cert.SerialNumber) == -1:
		i_PKI_SN = receiver.Cert.SerialNumber
	}
}
func (receiver *_PKI_Node) generate(inbound *x509.Certificate) { // generate cert for a Node
	switch {
	case inbound == nil:
		log.Debugf("no Cert data; ACTION: ignore")
		return
	}
	var (
		err error
	)
	log.Infof("generating a new cert")

	receiver.DER = &_PKI_Node_DER{
		Cert: _DER{},
		Key:  _DER{},
	}

	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("can't generate a new Key - %v", err)
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new Key - %v", err)
	}

	inc_big_Int(i_PKI_SN)
	inbound.SerialNumber = i_PKI_SN
	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
	case err != nil:
		log.Fatalf("can't create a new Cert - %v", err)
	}

	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Fatalf("can't parse a new Cert - %v", err)
	}

	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, ""); {
	case err != nil:
		log.Fatalf("can't encode a new P12 - %v", err)
	}
}

func (receiver __N_File_Data) read() (not_ok bool) {
	for dir := range receiver {
		receiver.check(dir, "")
		var (
			direntry []os.DirEntry
			err      error
			// fln      = strings_join("/", dir, strings_join(".", file, receiver[dir].ext))
			ext_l = len(receiver[dir].Ext)
		)
		switch {
		case ext_l > 0:
			ext_l++
		}

		switch direntry, err = os.ReadDir(dir.String()); {
		case err != nil:
			log.Warnf("file '%v' listing error '%v'; ACTION: report.", dir, err)
			// not_ok = true
			continue
		}

		for _, f := range direntry {
			switch {
			case !f.Type().IsRegular():
				log.Debugf("file '%v' is not a regular file; ACTION: skip", f.Name())
				continue
			}
			var (
				content _Content
				fn      = strings_join("/", dir, f.Name())
				fname   = _File_Name(f.Name()[:len(f.Name())-ext_l])
			)
			switch content, err = os.ReadFile(fn); {
			case err != nil:
				log.Warnf("file '%v' read error '%v'; ACTION: report.", fn, err)
				not_ok = true
				continue
			}
			// content.trim_space()
			receiver.put(dir, fname, "", content)
			receiver[dir].Sorted = append(receiver[dir].Sorted, fname)
		}
		sort.Slice(receiver[dir].Sorted, func(i, j int) bool {
			return receiver[dir].Sorted[i] < receiver[dir].Sorted[j]
		})

	}
	return !not_ok
}
func (receiver __N_File_Data) get(dir _Dir_Name, file _File_Name) ( /*not_ok bool,*/ outbound *_Content) {
	receiver.check(dir, file)
	switch _, flag := receiver[dir].File[file]; {
	case !flag:
		return
	}
	return /*!not_ok,*/ receiver[dir].File[file].Content
}
func (receiver __N_File_Data) put(dir _Dir_Name, file _File_Name, delimiter string, content any) /*not_ok bool*/ {
	receiver.check(dir, file)
	var (
		v_Content = _Content(convert_2_string(delimiter, content))
	)
	receiver[dir].File[file].Content = &v_Content
	// return !not_ok
}
func (receiver __N_File_Data) append(dir _Dir_Name, file _File_Name, delimiter string, content any) /*not_ok bool*/ {
	receiver.check(dir, file)
	var (
		v_Content = _Content(strings_join(delimiter, receiver[dir].File[file], content))
	)
	receiver[dir].File[file].Content = &v_Content
	return /*!not_ok*/
}
func (receiver __N_File_Data) check(dir _Dir_Name, file _File_Name) /*not_ok bool*/ {
	switch _, flag := receiver[dir]; {
	case !flag:
		log.Warnf("Dir '%v' definition doesn't exist; ACTION: create.", dir)
		receiver[dir] = &i_File_Data{
			File: __N_File_Data_Content{},
		}
	}
	switch {
	case len(file) != 0:
		switch _, flag := receiver[dir].File[file]; {
		case !flag:
			receiver[dir].File[file] = &i_File_Data_Content{}
			log.Debugf("File '%v' definition in Dir '%v' doesn't exist; ACTION: create.", dir, file)
			receiver[dir].File[file].Content = &_Content{}
		}
	}
}
func (receiver __N_File_Data) write() (not_ok bool) {
	for a, b := range receiver {
		switch err := os.MkdirAll(a.String(), os.ModeDir|0700); {
		case err != nil:
			log.Errorf("directory '%v' create error '%v'; ACTION: report.", a, err)
			not_ok = true
			continue
		}
		for c, d := range b.File {
			var (
				g = strings_join("/", a, strings_join(".", c, b.Ext))
			)
			switch err := os.WriteFile(g, *d.Content, 0600); {
			case err != nil:
				log.Errorf("file '%v' write error '%v'; ACTION: report.", g, err)
				not_ok = true
				continue
			}
		}
	}
	return !not_ok
}

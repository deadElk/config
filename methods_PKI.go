package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

func (receiver *_PKI_CA_Node) parse_DER(inbound *x509.Certificate) (status bool) { // parse/create a new CA Node
	switch {
	case receiver.DER == nil || len(receiver.DER.Cert) == 0 || len(receiver.DER.Key) == 0:
		log.Infof("no CA DER data; ACTION: generate a new CA Cert")
		return receiver.generate(inbound)
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
		return receiver.generate(inbound)
	}

	switch t.Key, err = x509.ParseECPrivateKey(receiver.DER.Key); {
	case err != nil:
		log.Warnf("can't parse CA Key - '%v'; ACTION: generate a new CA Cert", err)
		return receiver.generate(inbound)
	}

	switch {
	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
		// case t.Cert.PublicKey != t.Key.PublicKey:
		log.Warnf("CA Cert's signature doesn't match with CA Key's signature - '%v'; ACTION: generate a new CA Cert", err)
		return receiver.generate(inbound)
	}

	switch {
	case receiver.CA != nil: // CA is intermediate
		switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
		case err != nil:
			log.Warnf("CA's signature doesn't match with parent CA signature - '%v'; ACTION: generate a new CA Cert", err)
			return receiver.generate(inbound)
		}
		switch {
		case receiver.CA.CRL.HasExpired(time.Now()):
			log.Warnf("Expired CRL; ACTION: generate a new CRL.")
			status = t.generate_CRL()
		}
	}

	switch t.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err != nil:
		log.Warnf("can't parse CA CRL - '%v'; ACTION: generate a new CRL.", err)
		status = t.generate_CRL()
	case t.Cert.CheckCRLSignature(t.CRL) != nil:
		log.Warnf("CRL's signature doesn't match with CA's signature - '%v'; ACTION: generate a new CRL.", err)
		status = t.generate_CRL()
	}

	receiver.Cert = t.Cert
	receiver.Key = t.Key
	receiver.CRL = t.CRL
	receiver.DER.CRL = t.DER.CRL
	return status
}
func (receiver *_PKI_CA_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a CA Node
	switch {
	case inbound == nil:
		log.Fatalf("no CA Cert data; ACTION: report.")
		// return
	}
	var (
		err error
	)

	log.Infof("generating a new CA Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)

	receiver.DER = &_PKI_CA_Node_DER{Cert: _DER_Cert{}, Key: _DER_Key{}, CRL: _DER_CRL{}}

	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("can't generate a new CA Key - '%v'; ACTION: report.", err)
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new CA Key - '%v'; ACTION: report.", err)
	}

	var (
		ca_cert = inbound
		ca_key  = receiver.Key
	)
	switch {
	case receiver.CA != nil: // not self-signed
		ca_cert = receiver.CA.Cert
		ca_key = receiver.CA.Key
	}

	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, ca_cert, receiver.Key.Public(), ca_key); {
	case err != nil:
		log.Fatalf("can't create a new CA Cert - '%v'; ACTION: report.", err)
	}

	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Fatalf("can't parse a new CA Cert - '%v'; ACTION: report.", err)
	}

	receiver.generate_CRL()
	// receiver._DER_PEM()

	return true
}
func (receiver *_PKI_CA_Node) generate_CRL() (status bool) {
	var (
		err error
	)
	switch receiver.DER.CRL, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  x509.ECDSAWithSHA512,
		RevokedCertificates: nil,
		Number:              pki_crl_sn(),
		ThisUpdate:          time.Now(),
		NextUpdate:          pki_crl_expiry(),
		ExtraExtensions:     nil,
	}, receiver.Cert, receiver.Key); {
	case err != nil:
		log.Fatalf("can't create a new CA CRL - '%v'; ACTION: report.", err)
	}
	switch receiver.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err != nil:
		log.Fatalf("can't parse a new CA CRL - '%v'; ACTION: report.", err)
	}

	return true
}

// func (receiver *_PKI_CA_Node) _DER_PEM() (status bool) {
// 	receiver.PEM = &_PKI_CA_Node_PEM{
// 		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
// 		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
// 		CRL:  pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: receiver.DER.CRL}),
// 	}
// 	switch {
// 	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil || receiver.PEM.CRL == nil:
// 		log.Fatalf("can't create PEM for a CA; ACTION: report.")
// 	}
//
// 	return true
// }
// func (receiver *_PKI_Node) _DER_PEM() (status bool) {
// 	receiver.PEM = &_PKI_Node_PEM{
// 		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
// 		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
// 	}
// 	switch {
// 	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil:
// 		log.Fatalf("can't create PEM for a CA; ACTION: report.")
// 	}
//
// 	return true
// }
// func (receiver *_PKI_Host_Node) _DER_PEM() (status bool) {
// 	receiver.PEM = &_PKI_Host_Node_PEM{
// 		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
// 		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
// 	}
// 	switch {
// 	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil:
// 		log.Fatalf("can't convert Cert to PEM for a Host; ACTION: report.")
// 		_fatal()
// 	}
//
// 	return true
// }

func (receiver *_DER_Cert) _PEM() (outbound _PEM_Cert) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: *receiver})
}
func (receiver *_DER_Key) _PEM() (outbound _PEM_Key) {
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: *receiver})
}
func (receiver *_DER_CRL) _PEM() (outbound _PEM_CRL) {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: *receiver})
}
func (receiver *_DER_TLS_Server) _PEM() (outbound _PEM_TLS_Server) {
	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: *receiver})
}
func (receiver *_DER_TLS_Client) _PEM() (outbound _PEM_TLS_Client) {
	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: *receiver})
}

// func (receiver *_P12) get_FQDN() (fqdn _FQDN, status bool) {
// 	switch _, cert, _, err := pkcs12.DecodeChain(*receiver, pkcs12.DefaultPassword); {
// 	case err == nil:
// 		return _FQDN(cert.Subject.CommonName), true
// 	}
// 	return
// }

func (receiver _P12) parse(ca *_PKI_CA_Node) (outbound *_PKI_P12) {
	switch {
	case receiver == nil || len(receiver) == 0:
		log.Warnf("P12: no data.")
		return
	case ca == nil:
		log.Warnf("P12: no CA data.")
		return
	}
	var (
		err error
		key any
		t   = &_PKI_P12{DER: &_PKI_DER{}}
	)

	// TODO: VERY SLOW OP
	// switch key, t.Cert, _, err = pkcs12.DecodeChain(receiver, pkcs12.DefaultPassword); {
	switch key, t.Cert, err = pkcs12.Decode(receiver, pkcs12.DefaultPassword); {
	case err != nil:
		log.Warnf("P12: pkcs12.DecodeChain error - %v.", err)
		return
	}

	t.FQDN = _FQDN(t.Cert.Subject.CommonName)
	t.Serial = t.Cert.SerialNumber
	switch _, flag := i_PKI_P12[t.FQDN]; {
	case flag:
		log.Warnf("P12 '%v': already defined.", t.FQDN)
		return
	}
	switch _, flag := i_PKI[t.Serial]; {
	case flag:
		log.Warnf("P12 '%v': x509.Cert.SerialNumber '%v' already defined.", t.FQDN, t.Serial)
		return
	}

	switch {
	case reflect.TypeOf(key) != reflect.TypeOf(&ecdsa.PrivateKey{}):
		log.Warnf("P12 '%v': wrong key type (not ecdsa.PrivateKey).", t.FQDN)
		return
	}

	switch t.Key = key.(*ecdsa.PrivateKey); {
	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
		log.Warnf("P12 '%v': x509/ecdsa PublicKey not equal.", t.FQDN)
		return
	}

	// // TODO: VERY VERY VERY VERY SLOW OP
	// switch err = t.Cert.CheckSignatureFrom(ca.Cert); {
	// case err != nil:
	// 	log.Warnf("P12 '%v': x509.CheckSignatureFrom error - %v.", t.FQDN, err)
	// 	return
	// }

	switch t.DER.Key, err = x509.MarshalECPrivateKey(t.Key); {
	case err != nil:
		log.Warnf("P12 '%v': x509.MarshalECPrivateKey error - %v.", t.FQDN, err)
		return
	}

	// for _, b := range ca.CRL.TBSCertList.RevokedCertificates {
	// 	switch {
	// 	case b.SerialNumber == t.Cert.SerialNumber:
	// 		log.Warnf("P12 '%v': Cert is revoked.", t.FQDN)
	// 		return
	// 	}
	// }

	t.DER.Cert = t.Cert.Raw
	t.P12 = receiver
	i_PKI.put(t)

	return t
}

func (receiver *_PKI_CA_Node) verify_P12(fqdn _FQDN, inbound *x509.Certificate) (outbound *_PKI_P12, is_new bool) { // generate a new Cert
	switch {
	case receiver == nil:
		log.Fatalf("P12: no CA defined; ACTION: report.")
	}
	switch func() (outbound bool) {
		switch _, flag := i_PKI_P12[fqdn]; {
		case !flag:
			return false
		}
		// TODO: VERY VERY VERY VERY SLOW OP
		switch err := i_PKI_P12[fqdn].Cert.CheckSignatureFrom(receiver.Cert); {
		case err != nil:
			log.Warnf("P12 '%v': x509.CheckSignatureFrom error - %v.", fqdn, err)
			return false
		}
		for _, b := range receiver.CRL.TBSCertList.RevokedCertificates {
			switch {
			case b.SerialNumber == i_PKI_P12[fqdn].Cert.SerialNumber:
				log.Warnf("P12 '%v': Cert is revoked.", fqdn)
				return false
			}
		}
		return true
	}() {
	case true:
		return i_PKI_P12[fqdn], false
	}

	var (
		err error
		t   = &_PKI_P12{
			CA:     receiver,
			Cert:   nil,
			DER:    &_PKI_DER{},
			FQDN:   fqdn,
			Key:    nil,
			P12:    nil,
			Serial: nil,
		}
	)

	switch {
	case inbound == nil:
		log.Fatalf("P12: no data for a new Cert.")
	}

	log.Debugf("P12 '%v': generating a new Cert.", inbound.Subject.CommonName)

	switch t.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("P12: ecdsa.GenerateKey error %v", err)
	}

	switch t.DER.Key, err = x509.MarshalECPrivateKey(t.Key); {
	case err != nil:
		log.Fatalf("P12: x509.MarshalECPrivateKey error %v", err)
	}

	switch t.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, t.CA.Cert, t.Key.Public(), t.CA.Key); {
	case err != nil:
		log.Fatalf("P12: x509.CreateCertificate error %v", err)
	}

	switch t.Cert, err = x509.ParseCertificate(t.DER.Cert); {
	case err != nil:
		log.Fatalf("P12: x509.ParseCertificate error %v", err)
	}

	switch t.P12, err = pkcs12.Encode(rand.Reader, t.Key, t.Cert, nil, pkcs12.DefaultPassword); {
	case err != nil:
		log.Fatalf("P12: pkcs12.Encode error %v", err)
	}

	t.Serial = t.Cert.SerialNumber
	i_PKI.put(t)
	return t, true
}

// func (receiver *_P12) parse_Host_Node(ca *_PKI_CA_Node) /*(outbound *_PKI_Host_Node)*/ {
// 	var (
// 		host, flag = receiver.get_FQDN()
// 	)
// 	switch {
// 	case !flag:
// 		log.Warnf("LDAP DB: Domain '%v' Host '%v' malformed P12 data; ACTION: ignore.", ca.FQDN, host)
// 	case flag && ca.Host_Node[host] == nil:
// 		ca.Host_Node[host] = &_PKI_Host_Node{
// 			FQDN: host,
// 			CA:   ca,
// 			Cert: nil,
// 			Key:  nil,
// 			DER:  nil,
// 			P12:  *receiver,
// 		}
// 		// return i_PKI_DB.CA_Node[ca].Host_Node[host]
// 	case flag:
// 		log.Warnf("LDAP DB: Domain '%v' Host '%v' P12 data already loaded; ACTION: ignore.", ca.FQDN, host)
// 	}
// 	return
// }
// func (receiver *_P12) parse_Node(ca *_PKI_CA_Node) /*(outbound *_PKI_Node)*/ {
// 	var (
// 		host, flag = receiver.get_FQDN()
// 	)
// 	switch {
// 	case !flag:
// 		log.Warnf("LDAP DB: Domain '%v' Host '%v' malformed P12 data; ACTION: ignore.", ca.FQDN, host)
// 	case flag && ca.Node[host] == nil:
// 		ca.Node[host] = &_PKI_Node{
// 			FQDN: host,
// 			CA:   ca,
// 			Cert: nil,
// 			Key:  nil,
// 			DER:  nil,
// 			P12:  *receiver,
// 		}
// 		// return i_PKI_DB.CA_Node[ca].Node[host]
// 	case flag:
// 		log.Warnf("LDAP DB: Domain '%v' Host '%v' P12 data already loaded; ACTION: ignore.", ca.FQDN, host)
// 	}
// 	return
// }
//
// func (receiver *_PKI_Node) parse_P12(inbound *x509.Certificate) (status bool) { // parse P12 of a Node
// 	switch {
// 	case receiver.P12 == nil || len(receiver.P12) == 0:
// 		log.Warnf("no P12 data; ACTION: generate a new Cert")
// 		return receiver.generate(inbound)
// 	}
//
// 	var (
// 		err      error
// 		key      any
// 		ca_chain __Cert_Chain
// 		t        = &_PKI_Node{DER: &_PKI_Node_DER{}}
// 	)
//
// 	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, pkcs12.DefaultPassword); {
// 	case err != nil:
// 		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
// 		return receiver.generate(inbound)
// 	case len(ca_chain) != len(receiver.CA.CA_Chain):
// 		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
// 		return receiver.generate(inbound)
// 	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
// 		log.Warnf("unsupported Key type; ACTION: generate a new Cert")
// 		return receiver.generate(inbound)
// 	}
//
// 	for a, b := range ca_chain {
// 		switch {
// 		case receiver.CA.CA_Chain[a] != b:
// 			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
// 			return receiver.generate(inbound)
// 		}
// 	}
//
// 	switch t.Key = key.(*ecdsa.PrivateKey); {
// 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 		// case t.Cert.PublicKey != t.Key.PublicKey:
// 		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
// 		return receiver.generate(inbound)
// 	}
//
// 	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
// 	case err != nil:
// 		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
// 		return receiver.generate(inbound)
// 	}
//
// 	// P12 valid
// 	// receiver.P12 = inbound
//
// 	receiver.Cert = t.Cert
// 	receiver.Key = t.Key
//
// 	receiver.DER = &_PKI_Node_DER{
// 		Cert: receiver.Cert.Raw,
// 		Key:  nil,
// 	}
//
// 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// 	case err != nil:
// 		log.Fatalf("can't marshal a new Key - %v", err)
// 	}
//
// 	// receiver._DER_PEM()
//
// 	return
// }
// func (receiver *_PKI_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a Node
// 	switch {
// 	case inbound == nil:
// 		log.Fatalf("no Cert data; ACTION: ignore")
// 		// return
// 	}
// 	var (
// 		err error
// 	)
// 	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)
//
// 	receiver.DER = &_PKI_Node_DER{}
//
// 	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// 	case err != nil:
// 		log.Fatalf("can't generate a new Key - %v", err)
// 	}
//
// 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// 	case err != nil:
// 		log.Fatalf("can't marshal a new Key - %v", err)
// 	}
//
// 	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
// 	case err != nil:
// 		log.Fatalf("can't create a new Cert - %v", err)
// 	}
//
// 	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
// 	case err != nil:
// 		log.Fatalf("can't parse a new Cert - %v", err)
// 	}
//
// 	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, pkcs12.DefaultPassword); {
// 	case err != nil:
// 		log.Fatalf("can't encode a new P12 - %v", err)
// 	}
//
// 	// receiver._DER_PEM()
//
// 	return true
// }

func (receiver __BI_Any) put(inbound any) (status bool) {
	switch value := (inbound).(type) {
	case *_PKI_CA_Node:
		switch {
		case value != nil && receiver[value.Cert.SerialNumber] != nil:
			log.Warnf("PKI DB: CA Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
			return true
		case value != nil:
			receiver[value.Cert.SerialNumber] = value
			return true
		}
	case *_PKI_Host_Node:
		switch {
		case value != nil && receiver[value.Cert.SerialNumber] != nil:
			log.Warnf("PKI DB: Host Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
			return true
		case value != nil:
			receiver[value.Cert.SerialNumber] = value
			return true
		}
	case *_PKI_Node:
		switch {
		case value != nil && receiver[value.Cert.SerialNumber] != nil:
			log.Warnf("PKI DB: Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
			return true
		case value != nil:
			receiver[value.Cert.SerialNumber] = value
			return true
		}
	case *_PKI_P12:
		switch {
		case value != nil && receiver[value.Cert.SerialNumber] != nil:
			log.Warnf("PKI DB: Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
			return true
		case value != nil:
			receiver[value.Cert.SerialNumber] = value
			i_PKI_P12.put(value)
			return true
		}
	default:
		log.Warnf("PKI DB: unknown PKI Type; ACTION: none.")
		_fatal()
	}
	return
}
func (receiver __FQDN_PKI_P12) put(inbound *_PKI_P12) (status bool) {
	switch {
	case inbound != nil && receiver[inbound.FQDN] != nil:
		log.Warnf("PKI DB: CA Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", inbound.Cert.SerialNumber.String(), inbound.Cert.Subject.CommonName, inbound.Cert.Issuer.String())
		return true
	case inbound != nil:
		receiver[inbound.FQDN] = inbound
		return true
	default:
		log.Warnf("PKI P12 DB: nothing to do; ACTION: none.")
	}
	return
}
func (receiver __FQDN_PKI_P12) get_P12_string(fqdn ..._FQDN) (outbound []string) {
	for _, b := range fqdn {
		switch _, flag := receiver[b]; {
		case !flag:
			continue
		}
		outbound = append(outbound, receiver[b].P12.String())
	}
	return
}

// func (receiver *_PKI_Node) store() (status bool) {
// 	switch {
// 	case receiver != nil && i_PKI[receiver.Cert.SerialNumber] != nil:
// 		log.Warnf("PKI DB: Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", receiver.Cert.SerialNumber.String(), receiver.Cert.Subject.CommonName, receiver.Cert.Issuer.String())
// 		return true
// 	case receiver != nil:
// 		i_PKI[receiver.Cert.SerialNumber] = receiver
// 		return true
// 	}
// 	return
// }
// func (receiver *_PKI_Host_Node) parse_P12(inbound *x509.Certificate) (status bool) { // parse P12 of a Node
// 	switch {
// 	case receiver.P12 == nil || len(receiver.P12) == 0:
// 		log.Warnf("no P12 data; ACTION: generate a new Cert")
// 		return receiver.generate(inbound)
// 	}
//
// 	var (
// 		err      error
// 		key      any
// 		ca_chain __Cert_Chain
// 		t        = &_PKI_Host_Node{DER: &_PKI_Host_Node_DER{}}
// 	)
//
// 	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, pkcs12.DefaultPassword); {
// 	case err != nil:
// 		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
// 		return receiver.generate(inbound)
// 	case len(ca_chain) != len(receiver.CA.CA_Chain):
// 		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
// 		return receiver.generate(inbound)
// 	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
// 		log.Warnf("unsupported Key type; ACTION: generate a new Cert")
// 		return receiver.generate(inbound)
// 	}
//
// 	for a, b := range ca_chain {
// 		switch {
// 		case receiver.CA.CA_Chain[a] != b:
// 			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
// 			return receiver.generate(inbound)
// 		}
// 	}
//
// 	switch t.Key = key.(*ecdsa.PrivateKey); {
// 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 		// case t.Cert.PublicKey != t.Key.PublicKey:
// 		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
// 		return receiver.generate(inbound)
// 	}
//
// 	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
// 	case err != nil:
// 		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
// 		return receiver.generate(inbound)
// 	}
//
// 	receiver.Cert = t.Cert
// 	receiver.Key = t.Key
//
// 	receiver.DER = &_PKI_Host_Node_DER{
// 		Cert: receiver.Cert.Raw,
// 		Key:  nil,
// 	}
//
// 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// 	case err != nil:
// 		log.Fatalf("can't marshal a new Key - %v", err)
// 	}
//
// 	// receiver._DER_PEM()
//
// 	return
// }
// func (receiver *_PKI_Host_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a Node
// 	switch {
// 	case inbound == nil:
// 		log.Fatalf("no Cert data; ACTION: ignore")
// 		// return
// 	}
// 	var (
// 		err error
// 	)
// 	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)
//
// 	receiver.DER = &_PKI_Host_Node_DER{}
//
// 	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// 	case err != nil:
// 		log.Fatalf("can't generate a new Key - %v", err)
// 	}
//
// 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// 	case err != nil:
// 		log.Fatalf("can't marshal a new Key - %v", err)
// 	}
//
// 	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
// 	case err != nil:
// 		log.Fatalf("can't create a new Cert - %v", err)
// 	}
//
// 	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
// 	case err != nil:
// 		log.Fatalf("can't parse a new Cert - %v", err)
// 	}
//
// 	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, pkcs12.DefaultPassword); {
// 	case err != nil:
// 		log.Fatalf("can't encode a new P12 - %v", err)
// 	}
//
// 	// receiver._DER_PEM()
//
// 	return true
// }

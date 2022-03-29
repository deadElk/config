package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
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
	}

	switch t.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err != nil:
		log.Warnf("can't parse CA CRL - '%v'; ACTION: generate a new CA Cert", err)
		status = t.generate_CRL()
	case t.Cert.CheckCRLSignature(t.CRL) != nil:
		log.Warnf("CRL's signature doesn't match with CA's signature - '%v'; ACTION: generate a new CRL", err)
		status = t.generate_CRL()
	}

	receiver.Cert = t.Cert
	receiver.Key = t.Key
	receiver.CRL = t.CRL
	// receiver.DER.Cert = inbound.Cert
	// receiver.DER.Key = inbound.Key
	receiver.DER.CRL = t.DER.CRL

	receiver._DER_PEM()

	return status
}
func (receiver *_PKI_CA_Node) _DER_PEM() (status bool) {
	receiver.PEM = &_PKI_CA_Node_PEM{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
		CRL:  pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: receiver.DER.CRL}),
	}
	switch {
	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil || receiver.PEM.CRL == nil:
		log.Fatalf("can't create PEM for a CA; ACTION: report.")
	}

	return true
}
func (receiver *_PKI_Node) _DER_PEM() (status bool) {
	receiver.PEM = &_PKI_Node_PEM{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
	}
	switch {
	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil:
		log.Fatalf("can't create PEM for a CA; ACTION: report.")
	}

	return true
}
func (receiver *_PKI_Host_Node) _DER_PEM() (status bool) {
	receiver.PEM = &_PKI_Host_Node_PEM{
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
	}
	switch {
	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil:
		log.Fatalf("can't create PEM for a CA; ACTION: report.")
	}

	return true
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

	receiver.DER = &_PKI_CA_Node_DER{Cert: _DER{}, Key: _DER{}, CRL: _DER{}}

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
	receiver._DER_PEM()

	return true
}
func (receiver *_PKI_CA_Node) generate_CRL() (status bool) {
	var (
		err error
	)
	switch receiver.DER.CRL, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  x509.ECDSAWithSHA512,
		RevokedCertificates: nil,
		Number:              big.NewInt(time.Now().UnixNano()),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
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

func (receiver *_P12) get_FQDN() (fqdn _FQDN, status bool) {
	switch _, cert, _, err := pkcs12.DecodeChain(*receiver, pkcs12.DefaultPassword); {
	case err == nil:
		return _FQDN(cert.Subject.CommonName), true
	}
	return
}
func (receiver *_P12) parse_Host_Node(ca *_PKI_CA_Node) /*(outbound *_PKI_Host_Node)*/ {
	var (
		host, flag = receiver.get_FQDN()
	)
	switch {
	case !flag:
		log.Warnf("LDAP DB: Domain '%v' Host '%v' malformed P12 data; ACTION: ignore.", ca.FQDN, host)
	case flag && ca.Host_Node[host] == nil:
		ca.Host_Node[host] = &_PKI_Host_Node{
			FQDN: host,
			CA:   ca,
			Cert: nil,
			Key:  nil,
			DER:  nil,
			PEM:  nil,
			P12:  *receiver,
		}
		// return i_PKI_DB.CA_Node[ca].Host_Node[host]
	case flag:
		log.Warnf("LDAP DB: Domain '%v' Host '%v' P12 data already loaded; ACTION: ignore.", ca.FQDN, host)
	}
	return
}
func (receiver *_P12) parse_Node(ca *_PKI_CA_Node) /*(outbound *_PKI_Node)*/ {
	var (
		host, flag = receiver.get_FQDN()
	)
	switch {
	case !flag:
		log.Warnf("LDAP DB: Domain '%v' Host '%v' malformed P12 data; ACTION: ignore.", ca.FQDN, host)
	case flag && ca.Node[host] == nil:
		ca.Node[host] = &_PKI_Node{
			FQDN: host,
			CA:   ca,
			Cert: nil,
			Key:  nil,
			DER:  nil,
			PEM:  nil,
			P12:  *receiver,
		}
		// return i_PKI_DB.CA_Node[ca].Node[host]
	case flag:
		log.Warnf("LDAP DB: Domain '%v' Host '%v' P12 data already loaded; ACTION: ignore.", ca.FQDN, host)
	}
	return
}

func (receiver *_PKI_Node) parse_P12(inbound *x509.Certificate) (status bool) { // parse P12 of a Node
	switch {
	case receiver.P12 == nil || len(receiver.P12) == 0:
		log.Warnf("no P12 data; ACTION: generate a new Cert")
		return receiver.generate(inbound)
	}

	var (
		err      error
		key      any
		ca_chain __Cert_Chain
		t        = &_PKI_Node{DER: &_PKI_Node_DER{}}
	)

	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, pkcs12.DefaultPassword); {
	case err != nil:
		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
		return receiver.generate(inbound)
	case len(ca_chain) != len(receiver.CA.CA_Chain):
		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
		return receiver.generate(inbound)
	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
		log.Warnf("unsupported Key type; ACTION: generate a new Cert")
		return receiver.generate(inbound)
	}

	for a, b := range ca_chain {
		switch {
		case receiver.CA.CA_Chain[a] != b:
			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
			return receiver.generate(inbound)
		}
	}

	switch t.Key = key.(*ecdsa.PrivateKey); {
	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
		// case t.Cert.PublicKey != t.Key.PublicKey:
		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
		return receiver.generate(inbound)
	}

	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
	case err != nil:
		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
		return receiver.generate(inbound)
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

	receiver._DER_PEM()

	return
}
func (receiver *_PKI_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a Node
	switch {
	case inbound == nil:
		log.Fatalf("no Cert data; ACTION: ignore")
		// return
	}
	var (
		err error
	)
	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)

	receiver.DER = &_PKI_Node_DER{}

	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("can't generate a new Key - %v", err)
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new Key - %v", err)
	}

	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
	case err != nil:
		log.Fatalf("can't create a new Cert - %v", err)
	}

	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Fatalf("can't parse a new Cert - %v", err)
	}

	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, pkcs12.DefaultPassword); {
	case err != nil:
		log.Fatalf("can't encode a new P12 - %v", err)
	}

	receiver._DER_PEM()

	return true
}

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

func (receiver *_PKI_Host_Node) parse_P12(inbound *x509.Certificate) (status bool) { // parse P12 of a Node
	switch {
	case receiver.P12 == nil || len(receiver.P12) == 0:
		log.Warnf("no P12 data; ACTION: generate a new Cert")
		return receiver.generate(inbound)
	}

	var (
		err      error
		key      any
		ca_chain __Cert_Chain
		t        = &_PKI_Node{DER: &_PKI_Node_DER{}}
	)

	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, pkcs12.DefaultPassword); {
	case err != nil:
		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
		return receiver.generate(inbound)
	case len(ca_chain) != len(receiver.CA.CA_Chain):
		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
		return receiver.generate(inbound)
	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
		log.Warnf("unsupported Key type; ACTION: generate a new Cert")
		return receiver.generate(inbound)
	}

	for a, b := range ca_chain {
		switch {
		case receiver.CA.CA_Chain[a] != b:
			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
			return receiver.generate(inbound)
		}
	}

	switch t.Key = key.(*ecdsa.PrivateKey); {
	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
		// case t.Cert.PublicKey != t.Key.PublicKey:
		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
		return receiver.generate(inbound)
	}

	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
	case err != nil:
		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
		return receiver.generate(inbound)
	}

	// P12 valid
	// receiver.P12 = inbound

	receiver.Cert = t.Cert
	receiver.Key = t.Key

	receiver.DER = &_PKI_Host_Node_DER{
		Cert: receiver.Cert.Raw,
		Key:  nil,
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new Key - %v", err)
	}

	receiver._DER_PEM()

	return
}
func (receiver *_PKI_Host_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a Node
	switch {
	case inbound == nil:
		log.Fatalf("no Cert data; ACTION: ignore")
		// return
	}
	var (
		err error
	)
	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)

	receiver.DER = &_PKI_Host_Node_DER{}

	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("can't generate a new Key - %v", err)
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("can't marshal a new Key - %v", err)
	}

	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
	case err != nil:
		log.Fatalf("can't create a new Cert - %v", err)
	}

	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Fatalf("can't parse a new Cert - %v", err)
	}

	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, pkcs12.DefaultPassword); {
	case err != nil:
		log.Fatalf("can't encode a new P12 - %v", err)
	}

	receiver._DER_PEM()

	return true
}

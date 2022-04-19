package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"reflect"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
	"software.sslmate.com/src/go-pkcs12"
)

// func (receiver *_PKI_CA_Node) parse_DER(inbound *x509.Certificate) (status bool) { // parse/create a new CA Node
// 	switch {
// 	case receiver.DER == nil || len(receiver.DER.Cert) == 0 || len(receiver.DER.Key) == 0:
// 		log.Infof("no CA DER data; ACTION: generate a new CA Cert")
// 		return receiver.generate(inbound)
// 	}
//
// 	var (
// 		err error
// 		// key any
// 		t = &_PKI_CA_Node{
// 			DER: &_PKI_CA_Node_DER{
// 				Cert: receiver.DER.Cert,
// 				Key:  receiver.DER.Key,
// 				CRL:  receiver.DER.CRL,
// 			},
// 		}
// 	)
//
// 	switch t.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
// 	case err != nil:
// 		log.Warnf("can't parse CA Cert - '%v'; ACTION: generate a new CA Cert", err)
// 		return receiver.generate(inbound)
// 	}
//
// 	switch t.Key, err = x509.ParseECPrivateKey(receiver.DER.Key); {
// 	case err != nil:
// 		log.Warnf("can't parse CA Key - '%v'; ACTION: generate a new CA Cert", err)
// 		return receiver.generate(inbound)
// 	}
// 	// switch key, err = x509.ParsePKCS8PrivateKey(receiver.DER.Key); {
// 	// case err != nil:
// 	// 	log.Warnf("can't parse CA Key - '%v'; ACTION: generate a new CA Cert", err)
// 	// 	return receiver.generate(inbound)
// 	// }
// 	// switch {
// 	// case reflect.TypeOf(key) != reflect.TypeOf(ed25519.PrivateKey{}):
// 	// 	log.Warnf("P12 '%v': wrong key type (not ecdsa.PrivateKey).", t.FQDN)
// 	// 	return
// 	// }
// 	// switch t.Key = key.(*ecdsa.PrivateKey); {
// 	// case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 	// 	log.Warnf("P12 '%v': x509/ecdsa PublicKey not equal.", t.FQDN)
// 	// 	return
// 	// }
// 	// switch t.Key = key.(ed25519.PrivateKey); {
// 	// case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 	// 	log.Warnf("P12 '%v': x509/ed25519 PublicKey not equal.", t.FQDN)
// 	// 	return
// 	// }
//
// 	switch {
// 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 		// case t.Cert.PublicKey != t.Key.PublicKey:
// 		log.Warnf("CA Cert's signature doesn't match with CA Key's signature - '%v'; ACTION: generate a new CA Cert", err)
// 		return receiver.generate(inbound)
// 	}
//
// 	switch {
// 	case receiver.CA != nil: // CA is intermediate
// 		switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
// 		case err != nil:
// 			log.Warnf("CA's signature doesn't match with parent CA signature - '%v'; ACTION: generate a new CA Cert", err)
// 			return receiver.generate(inbound)
// 		}
// 		switch {
// 		case receiver.CA.CRL.HasExpired(time.Now()):
// 			log.Warnf("Expired CRL; ACTION: generate a new CRL.")
// 			status = t.create_CRL()
// 		}
// 	}
//
// 	switch t.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
// 	case err != nil:
// 		log.Warnf("can't parse CA CRL - '%v'; ACTION: generate a new CRL.", err)
// 		status = t.create_CRL()
// 	case t.Cert.CheckCRLSignature(t.CRL) != nil:
// 		log.Warnf("CRL's signature doesn't match with CA's signature - '%v'; ACTION: generate a new CRL.", err)
// 		status = t.create_CRL()
// 	}
//
// 	receiver.Cert = t.Cert
// 	receiver.Key = t.Key
// 	receiver.CRL = t.CRL
// 	receiver.DER.CRL = t.DER.CRL
// 	return status
// }
// func (receiver *_PKI_CA_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a CA Node
// 	switch {
// 	case inbound == nil:
// 		log.Fatalf("no CA Cert data; ACTION: report.")
// 		// return
// 	}
// 	var (
// 		err error
// 	)
//
// 	log.Infof("generating a new CA Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)
//
// 	receiver.DER = &_PKI_CA_Node_DER{Cert: _DER_Cert{}, Key: _DER_Key{}, CRL: _DER_CRL{}}
//
// 	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// 	case err != nil:
// 		log.Fatalf("can't generate a new CA Key - '%v'; ACTION: report.", err)
// 	}
// 	// switch _, receiver.Key, err = ed25519.GenerateKey(rand.Reader); {
// 	// case err != nil:
// 	// 	log.Fatalf("can't generate a new CA Key - '%v'; ACTION: report.", err)
// 	// }
//
// 	// switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// 	// case err != nil:
// 	// 	log.Fatalf("can't marshal a new CA Key - '%v'; ACTION: report.", err)
// 	// }
// 	switch receiver.DER.Key, err = x509.MarshalPKCS8PrivateKey(receiver.Key); {
// 	case err != nil:
// 		log.Fatalf("can't marshal a new CA Key - '%v'; ACTION: report.", err)
// 	}
//
// 	var (
// 		ca_cert = inbound
// 		ca_key  = receiver.Key
// 	)
// 	switch {
// 	case receiver.CA != nil: // not self-signed
// 		ca_cert = receiver.CA.Cert
// 		ca_key = receiver.CA.Key
// 	}
//
// 	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, ca_cert, receiver.Key.Public(), ca_key); {
// 	case err != nil:
// 		log.Fatalf("can't create a new CA Cert - '%v'; ACTION: report.", err)
// 	}
//
// 	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
// 	case err != nil:
// 		log.Fatalf("can't parse a new CA Cert - '%v'; ACTION: report.", err)
// 	}
//
// 	receiver.create_CRL()
// 	// receiver._DER_PEM()
//
// 	return true
// }
// func (receiver *_PKI_CA_Node) create_CRL() (status bool) {
// 	var (
// 		err error
// 	)
// 	switch receiver.DER.CRL, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
// 		SignatureAlgorithm: x509.ECDSAWithSHA512,
// 		// SignatureAlgorithm:  x509.PureEd25519,
// 		RevokedCertificates: nil,
// 		Number:              pki_crl_sn(),
// 		ThisUpdate:          time.Now(),
// 		NextUpdate:          pki_crl_expiry(),
// 		ExtraExtensions:     nil,
// 	}, receiver.Cert, receiver.Key); {
// 	case err != nil:
// 		log.Fatalf("can't create a new CA CRL - '%v'; ACTION: report.", err)
// 	}
// 	switch receiver.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
// 	case err != nil:
// 		log.Fatalf("can't parse a new CA CRL - '%v'; ACTION: report.", err)
// 	}
//
// 	return true
// }
//
// // func (receiver *_PKI_CA_Node) _DER_PEM() (status bool) {
// // 	receiver.PEM = &_PKI_CA_Node_PEM{
// // 		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
// // 		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
// // 		CRL:  pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: receiver.DER.CRL}),
// // 	}
// // 	switch {
// // 	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil || receiver.PEM.CRL == nil:
// // 		log.Fatalf("can't create PEM for a CA; ACTION: report.")
// // 	}
// //
// // 	return true
// // }
// // func (receiver *_PKI_Node) _DER_PEM() (status bool) {
// // 	receiver.PEM = &_PKI_Node_PEM{
// // 		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
// // 		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
// // 	}
// // 	switch {
// // 	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil:
// // 		log.Fatalf("can't create PEM for a CA; ACTION: report.")
// // 	}
// //
// // 	return true
// // }
// // func (receiver *_PKI_Host_Node) _DER_PEM() (status bool) {
// // 	receiver.PEM = &_PKI_Host_Node_PEM{
// // 		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.DER.Cert}),
// // 		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}),
// // 	}
// // 	switch {
// // 	case receiver.PEM.Cert == nil || receiver.PEM.Key == nil:
// // 		log.Fatalf("can't convert Cert to PEM for a Host; ACTION: report.")
// // 		_fatal()
// // 	}
// //
// // 	return true
// // }
//
// // func (receiver *_DER_Cert) _PEM() (outbound _PEM_Cert) {
// // 	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: *receiver})
// // }
// // func (receiver *_DER_Key) _PEM() (outbound _PEM_Key) {
// // 	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: *receiver})
// // 	// return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: *receiver})
// // }
// // func (receiver *_DER_CRL) _PEM() (outbound _PEM_CRL) {
// // 	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: *receiver})
// // }
// //
// // func (receiver *_DER_TLS_Server) _PEM() (outbound _PEM_TLS_Server) {
// // 	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: *receiver})
// // }
// // func (receiver *_DER_TLS_Client) _PEM() (outbound _PEM_TLS_Client) {
// // 	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: *receiver})
// // }
//
// // func (receiver _P12) parse(ca *_PKI_CA_Node) (outbound *_PKI_P12) {
// // 	switch {
// // 	case receiver == nil || len(receiver) == 0:
// // 		log.Warnf("P12: no data.")
// // 		return
// // 	case ca == nil:
// // 		log.Warnf("P12: no CA data.")
// // 		return
// // 	}
// //
// // 	// type contentInfo struct {
// // 	// 	ContentType asn1.ObjectIdentifier
// // 	// 	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
// // 	// }
// // 	// type digestInfo struct {
// // 	// 	Algorithm pkix.AlgorithmIdentifier
// // 	// 	Digest    []byte
// // 	// }
// // 	// type macData struct {
// // 	// 	Mac        digestInfo
// // 	// 	MacSalt    []byte
// // 	// 	Iterations int `asn1:"optional,default:1"`
// // 	// }
// // 	// type pfxPdu struct {
// // 	// 	Version  int
// // 	// 	AuthSafe contentInfo
// // 	// 	MacData  macData `asn1:"optional"`
// // 	// }
// //
// // 	var (
// // 		err error
// // 		key any
// // 		t   = &_PKI_P12{DER: &_PKI_DER{}}
// // 		// pfx = new(pfxPdu)
// // 	)
// //
// // 	// TODO: VERY SLOW OP
// // 	// switch key, t.Cert, _, err = pkcs12.DecodeChain(receiver, pkcs12.DefaultPassword); {
// // 	// a, b := asn1.Unmarshal(receiver, pfx)
// // 	switch key, t.Cert, err = pkcs12.Decode(receiver, pkcs12.DefaultPassword); {
// // 	case err != nil:
// // 		log.Warnf("P12: pkcs12.DecodeChain error - %v.", err)
// // 		return
// // 	}
// //
// // 	t.FQDN = _FQDN(t.Cert.Subject.CommonName)
// // 	t.SN = t.Cert.SerialNumber
// // 	switch _, flag := i_PKI_P12[t.FQDN]; {
// // 	case flag:
// // 		log.Warnf("P12 '%v': already defined.", t.FQDN)
// // 		return
// // 	}
// // 	switch _, flag := i_PKI[t.SN]; {
// // 	case flag:
// // 		log.Warnf("P12 '%v': x509.Cert.SerialNumber '%v' already defined.", t.FQDN, t.SN)
// // 		return
// // 	}
// //
// // 	switch {
// // 	case reflect.TypeOf(key) != reflect.TypeOf(&ecdsa.PrivateKey{}):
// // 		log.Warnf("P12 '%v': wrong key type (not ecdsa.PrivateKey).", t.FQDN)
// // 		return
// // 	}
// // 	// switch {
// // 	// case reflect.TypeOf(key) != reflect.TypeOf(ed25519.PrivateKey{}):
// // 	// 	log.Warnf("P12 '%v': wrong key type (not ed25519.PrivateKey).", t.FQDN)
// // 	// 	return
// // 	// }
// //
// // 	switch t.Key = key.(*ecdsa.PrivateKey); {
// // 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// // 		log.Warnf("P12 '%v': x509/ecdsa PublicKey not equal.", t.FQDN)
// // 		return
// // 	}
// // 	// switch t.Key = key.(ed25519.PrivateKey); {
// // 	// case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// // 	// 	log.Warnf("P12 '%v': x509/ed25519 PublicKey not equal.", t.FQDN)
// // 	// 	return
// // 	// }
// //
// // 	// // // // TODO: VERY VERY VERY VERY SLOW OP
// // 	// // // // switch err = t.Cert.CheckSignatureFrom(ca.Cert); {
// // 	// // // // case err != nil:
// // 	// // // // 	log.Warnf("P12 '%v': x509.CheckSignatureFrom error - %v.", t.FQDN, err)
// // 	// // // // 	return
// // 	// // // // }
// //
// // 	// switch t.DER.Key, err = x509.MarshalECPrivateKey(t.Key); {
// // 	// case err != nil:
// // 	// 	log.Warnf("P12 '%v': x509.MarshalECPrivateKey error - %v.", t.FQDN, err)
// // 	// 	return
// // 	// }
// // 	switch t.DER.Key, err = x509.MarshalPKCS8PrivateKey(t.Key); {
// // 	case err != nil:
// // 		log.Warnf("P12 '%v': x509.MarshalPKCS8PrivateKey error - %v.", t.FQDN, err)
// // 		return
// // 	}
// //
// // 	// for _, b := range ca.CRL.TBSCertList.RevokedCertificates {
// // 	// 	switch {
// // 	// 	case b.SerialNumber == t.Cert.SerialNumber:
// // 	// 		log.Warnf("P12 '%v': Cert is revoked.", t.FQDN)
// // 	// 		return
// // 	// 	}
// // 	// }
// //
// // 	t.DER.Cert = t.Cert.Raw
// // 	t.P12 = receiver
// // 	i_PKI.put(t)
// //
// // 	// log.Infof("%+v %+v %+v %+v %+v", pfx, a, b, t.Key, t.Cert.Raw)
// //
// // 	return t
// // }
// func (receiver _PEM_Container) parse(ca *_PKI_CA_Node) (outbound *_PKI_Container) {
// 	switch {
// 	case receiver == nil || len(receiver) == 0:
// 		log.Warnf("P12: no data.")
// 		return
// 	case ca == nil:
// 		log.Warnf("P12: no CA data.")
// 		return
// 	}
//
// 	var (
// 		err error
// 		key any
// 		t   = &_PKI_Container{DER: &_PKI_DER{}}
// 	)
//
// 	// TODO: VERY SLOW OP
// 	// switch key, t.Cert, _, err = pkcs12.DecodeChain(receiver, pkcs12.DefaultPassword); {
// 	switch key, t.Cert, err = pkcs12.Decode(receiver, pkcs12.DefaultPassword); {
// 	case err != nil:
// 		log.Warnf("P12: pkcs12.DecodeChain error - %v.", err)
// 		return
// 	}
//
// 	t.FQDN = _FQDN(t.Cert.Subject.CommonName)
// 	t.SN = t.Cert.SerialNumber
// 	switch _, flag := i_PKI_P12[t.FQDN]; {
// 	case flag:
// 		log.Warnf("P12 '%v': already defined.", t.FQDN)
// 		return
// 	}
// 	switch _, flag := i_PKI[t.SN]; {
// 	case flag:
// 		log.Warnf("P12 '%v': x509.Cert.SerialNumber '%v' already defined.", t.FQDN, t.SN)
// 		return
// 	}
//
// 	switch {
// 	case reflect.TypeOf(key) != reflect.TypeOf(&ecdsa.PrivateKey{}):
// 		log.Warnf("P12 '%v': wrong key type (not ecdsa.PrivateKey).", t.FQDN)
// 		return
// 	}
// 	// switch {
// 	// case reflect.TypeOf(key) != reflect.TypeOf(ed25519.PrivateKey{}):
// 	// 	log.Warnf("P12 '%v': wrong key type (not ed25519.PrivateKey).", t.FQDN)
// 	// 	return
// 	// }
//
// 	switch t.Key = key.(*ecdsa.PrivateKey); {
// 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 		log.Warnf("P12 '%v': x509/ecdsa PublicKey not equal.", t.FQDN)
// 		return
// 	}
// 	// switch t.Key = key.(ed25519.PrivateKey); {
// 	// case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// 	// 	log.Warnf("P12 '%v': x509/ed25519 PublicKey not equal.", t.FQDN)
// 	// 	return
// 	// }
//
// 	// // // // TODO: VERY VERY VERY VERY SLOW OP
// 	// // // // switch err = t.Cert.CheckSignatureFrom(ca.Cert); {
// 	// // // // case err != nil:
// 	// // // // 	log.Warnf("P12 '%v': x509.CheckSignatureFrom error - %v.", t.FQDN, err)
// 	// // // // 	return
// 	// // // // }
//
// 	// switch t.DER.Key, err = x509.MarshalECPrivateKey(t.Key); {
// 	// case err != nil:
// 	// 	log.Warnf("P12 '%v': x509.MarshalECPrivateKey error - %v.", t.FQDN, err)
// 	// 	return
// 	// }
// 	switch t.DER.Key, err = x509.MarshalPKCS8PrivateKey(t.Key); {
// 	case err != nil:
// 		log.Warnf("P12 '%v': x509.MarshalPKCS8PrivateKey error - %v.", t.FQDN, err)
// 		return
// 	}
//
// 	// for _, b := range ca.CRL.TBSCertList.RevokedCertificates {
// 	// 	switch {
// 	// 	case b.SerialNumber == t.Cert.SerialNumber:
// 	// 		log.Warnf("P12 '%v': Cert is revoked.", t.FQDN)
// 	// 		return
// 	// 	}
// 	// }
//
// 	t.DER.Cert = t.Cert.Raw
// 	t.P12 = receiver
// 	i_PKI.put(t)
//
// 	// log.Infof("%+v %+v %+v %+v %+v", pfx, a, b, t.Key, t.Cert.Raw)
//
// 	return t
// }
//
// func (receiver *_PKI_CA_Node) verify_P12(fqdn _FQDN, inbound *x509.Certificate) (outbound *_PKI_Container, is_new bool) { // generate a new Cert
// 	switch {
// 	case receiver == nil:
// 		log.Fatalf("P12: no CA defined; ACTION: report.")
// 	}
// 	switch func() (outbound bool) {
// 		switch _, flag := i_PKI_P12[fqdn]; {
// 		case !flag:
// 			return false
// 		}
// 		// TODO: VERY VERY VERY VERY SLOW OP
// 		switch err := i_PKI_P12[fqdn].Cert.CheckSignatureFrom(receiver.Cert); {
// 		case err != nil:
// 			log.Warnf("P12 '%v': x509.CheckSignatureFrom error - %v.", fqdn, err)
// 			return false
// 		}
// 		for _, b := range receiver.CRL.TBSCertList.RevokedCertificates {
// 			switch {
// 			case b.SerialNumber == i_PKI_P12[fqdn].Cert.SerialNumber:
// 				log.Warnf("P12 '%v': Cert is revoked.", fqdn)
// 				return false
// 			}
// 		}
// 		return true
// 	}() {
// 	case true:
// 		return i_PKI_P12[fqdn], false
// 	}
//
// 	var (
// 		err error
// 		t   = &_PKI_Container{
// 			CA:     receiver,
// 			Cert:   nil,
// 			SN: nil,
// 			PEM:    nil,
// 			DER:    &_PKI_DER{},
// 			FQDN:   fqdn,
// 			Key:    nil,
// 		}
// 	)
//
// 	switch {
// 	case inbound == nil:
// 		log.Fatalf("P12: no data for a new Cert.")
// 	}
//
// 	log.Debugf("P12 '%v': generating a new Cert.", inbound.Subject.CommonName)
//
// 	switch t.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// 	case err != nil:
// 		log.Fatalf("P12: ecdsa.GenerateKey error %v", err)
// 	}
// 	// switch _, t.Key, err = ed25519.GenerateKey(rand.Reader); {
// 	// case err != nil:
// 	// 	log.Fatalf("P12: ed25519.GenerateKey error %v", err)
// 	// }
//
// 	switch t.DER.Key, err = x509.MarshalECPrivateKey(t.Key); {
// 	case err != nil:
// 		log.Fatalf("P12: x509.MarshalECPrivateKey error %v", err)
// 	}
// 	// switch t.DER.Key, err = x509.MarshalPKCS8PrivateKey(t.Key); {
// 	// case err != nil:
// 	// 	log.Fatalf("P12: x509.MarshalPKCS8PrivateKey error %v", err)
// 	// }
//
// 	switch t.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, t.CA.Cert, t.Key.Public(), t.CA.Key); {
// 	case err != nil:
// 		log.Fatalf("P12: x509.CreateCertificate error %v", err)
// 	}
//
// 	switch t.Cert, err = x509.ParseCertificate(t.DER.Cert); {
// 	case err != nil:
// 		log.Fatalf("P12: x509.ParseCertificate error %v", err)
// 	}
//
// 	switch t.P12, err = pkcs12.Encode(rand.Reader, t.Key, t.Cert, nil, pkcs12.DefaultPassword); {
// 	case err != nil:
// 		log.Fatalf("P12: pkcs12.Encode error %v", err)
// 	}
//
// 	t.SN = t.Cert.SerialNumber
// 	i_PKI.put(t)
// 	return t, true
// }
//
// // func (receiver *_P12) parse_Host_Node(ca *_PKI_CA_Node) /*(outbound *_PKI_Host_Node)*/ {
// // 	var (
// // 		host, flag = receiver.get_FQDN()
// // 	)
// // 	switch {
// // 	case !flag:
// // 		log.Warnf("LDAP DB: Domain '%v' Host '%v' malformed P12 data; ACTION: ignore.", ca.FQDN, host)
// // 	case flag && ca.Host_Node[host] == nil:
// // 		ca.Host_Node[host] = &_PKI_Host_Node{
// // 			FQDN: host,
// // 			CA:   ca,
// // 			Cert: nil,
// // 			Key:  nil,
// // 			DER:  nil,
// // 			P12:  *receiver,
// // 		}
// // 		// return i_PKI_DB.CA_Node[ca].Host_Node[host]
// // 	case flag:
// // 		log.Warnf("LDAP DB: Domain '%v' Host '%v' P12 data already loaded; ACTION: ignore.", ca.FQDN, host)
// // 	}
// // 	return
// // }
//
// // func (receiver *_P12) parse_Node(ca *_PKI_CA_Node) /*(outbound *_PKI_Node)*/ {
// // 	var (
// // 		host, flag = receiver.get_FQDN()
// // 	)
// // 	switch {
// // 	case !flag:
// // 		log.Warnf("LDAP DB: Domain '%v' Host '%v' malformed P12 data; ACTION: ignore.", ca.FQDN, host)
// // 	case flag && ca.Node[host] == nil:
// // 		ca.Node[host] = &_PKI_Node{
// // 			FQDN: host,
// // 			CA:   ca,
// // 			Cert: nil,
// // 			Key:  nil,
// // 			DER:  nil,
// // 			P12:  *receiver,
// // 		}
// // 		// return i_PKI_DB.CA_Node[ca].Node[host]
// // 	case flag:
// // 		log.Warnf("LDAP DB: Domain '%v' Host '%v' P12 data already loaded; ACTION: ignore.", ca.FQDN, host)
// // 	}
// // 	return
// // }
//
// // func (receiver *_PKI_Node) parse_P12(inbound *x509.Certificate) (status bool) { // parse P12 of a Node
// // 	switch {
// // 	case receiver.P12 == nil || len(receiver.P12) == 0:
// // 		log.Warnf("no P12 data; ACTION: generate a new Cert")
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	var (
// // 		err      error
// // 		key      any
// // 		ca_chain __Cert_Chain
// // 		t        = &_PKI_Node{DER: &_PKI_Node_DER{}}
// // 	)
// //
// // 	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, pkcs12.DefaultPassword); {
// // 	case err != nil:
// // 		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
// // 		return receiver.generate(inbound)
// // 	case len(ca_chain) != len(receiver.CA.CA_Chain):
// // 		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
// // 		return receiver.generate(inbound)
// // 	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
// // 		log.Warnf("unsupported Key type; ACTION: generate a new Cert")
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	for a, b := range ca_chain {
// // 		switch {
// // 		case receiver.CA.CA_Chain[a] != b:
// // 			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
// // 			return receiver.generate(inbound)
// // 		}
// // 	}
// //
// // 	switch t.Key = key.(*ecdsa.PrivateKey); {
// // 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// // 		// case t.Cert.PublicKey != t.Key.PublicKey:
// // 		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
// // 	case err != nil:
// // 		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	// P12 valid
// // 	// receiver.P12 = inbound
// //
// // 	receiver.Cert = t.Cert
// // 	receiver.Key = t.Key
// //
// // 	receiver.DER = &_PKI_Node_DER{
// // 		Cert: receiver.Cert.Raw,
// // 		Key:  nil,
// // 	}
// //
// // 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// // 	case err != nil:
// // 		log.Fatalf("can't marshal a new Key - %v", err)
// // 	}
// //
// // 	// receiver._DER_PEM()
// //
// // 	return
// // }
//
// // func (receiver *_PKI_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a Node
// // 	switch {
// // 	case inbound == nil:
// // 		log.Fatalf("no Cert data; ACTION: ignore")
// // 		// return
// // 	}
// // 	var (
// // 		err error
// // 	)
// // 	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)
// //
// // 	receiver.DER = &_PKI_Node_DER{}
// //
// // 	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// // 	case err != nil:
// // 		log.Fatalf("can't generate a new Key - %v", err)
// // 	}
// //
// // 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// // 	case err != nil:
// // 		log.Fatalf("can't marshal a new Key - %v", err)
// // 	}
// //
// // 	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
// // 	case err != nil:
// // 		log.Fatalf("can't create a new Cert - %v", err)
// // 	}
// //
// // 	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
// // 	case err != nil:
// // 		log.Fatalf("can't parse a new Cert - %v", err)
// // 	}
// //
// // 	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, pkcs12.DefaultPassword); {
// // 	case err != nil:
// // 		log.Fatalf("can't encode a new P12 - %v", err)
// // 	}
// //
// // 	// receiver._DER_PEM()
// //
// // 	return true
// // }
//
// func (receiver __BI_Any) put(inbound any) (status bool) {
// 	switch value := (inbound).(type) {
// 	case *_PKI_CA_Node:
// 		switch {
// 		case value != nil && receiver[value.Cert.SerialNumber] != nil:
// 			log.Warnf("PKI DB: CA Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
// 			return true
// 		case value != nil:
// 			receiver[value.Cert.SerialNumber] = value
// 			return true
// 		}
// 	case *_PKI_Host_Node:
// 		switch {
// 		case value != nil && receiver[value.Cert.SerialNumber] != nil:
// 			log.Warnf("PKI DB: Host Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
// 			return true
// 		case value != nil:
// 			receiver[value.Cert.SerialNumber] = value
// 			return true
// 		}
// 	case *_PKI_Node:
// 		switch {
// 		case value != nil && receiver[value.Cert.SerialNumber] != nil:
// 			log.Warnf("PKI DB: Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
// 			return true
// 		case value != nil:
// 			receiver[value.Cert.SerialNumber] = value
// 			return true
// 		}
// 	case *_PKI_Container:
// 		switch {
// 		case value != nil && receiver[value.Cert.SerialNumber] != nil:
// 			log.Warnf("PKI DB: Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", value.Cert.SerialNumber.String(), value.Cert.Subject.CommonName, value.Cert.Issuer.String())
// 			return true
// 		case value != nil:
// 			receiver[value.Cert.SerialNumber] = value
// 			i_PKI_P12.put(value)
// 			return true
// 		}
// 	default:
// 		log.Warnf("PKI DB: unknown PKI Type; ACTION: none.")
// 		_fatal()
// 	}
// 	return
// }
// func (receiver __FQDN_PKI_Container) put(inbound *_PKI_Container) (status bool) {
// 	switch {
// 	case inbound != nil && receiver[inbound.FQDN] != nil:
// 		log.Warnf("PKI DB: CA Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", inbound.Cert.SerialNumber.String(), inbound.Cert.Subject.CommonName, inbound.Cert.Issuer.String())
// 		return true
// 	case inbound != nil:
// 		receiver[inbound.FQDN] = inbound
// 		return true
// 	default:
// 		log.Warnf("PKI P12 DB: nothing to do; ACTION: none.")
// 	}
// 	return
// }
//
// // func (receiver __FQDN_PKI_Container) get_P12_string(fqdn ..._FQDN) (outbound []string) {
// // 	for _, b := range fqdn {
// // 		switch _, flag := receiver[b]; {
// // 		case !flag:
// // 			continue
// // 		}
// // 		outbound = append(outbound, receiver[b].P12.String())
// // 	}
// // 	return
// // }
//
// // func (receiver *_PKI_Node) store() (status bool) {
// // 	switch {
// // 	case receiver != nil && i_PKI[receiver.Cert.SerialNumber] != nil:
// // 		log.Warnf("PKI DB: Cert SN '%v', CN '%v', Issuer '%v' already exist; ACTION: none.", receiver.Cert.SerialNumber.String(), receiver.Cert.Subject.CommonName, receiver.Cert.Issuer.String())
// // 		return true
// // 	case receiver != nil:
// // 		i_PKI[receiver.Cert.SerialNumber] = receiver
// // 		return true
// // 	}
// // 	return
// // }
//
// // func (receiver *_PKI_Host_Node) parse_P12(inbound *x509.Certificate) (status bool) { // parse P12 of a Node
// // 	switch {
// // 	case receiver.P12 == nil || len(receiver.P12) == 0:
// // 		log.Warnf("no P12 data; ACTION: generate a new Cert")
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	var (
// // 		err      error
// // 		key      any
// // 		ca_chain __Cert_Chain
// // 		t        = &_PKI_Host_Node{DER: &_PKI_Host_Node_DER{}}
// // 	)
// //
// // 	switch key, t.Cert, ca_chain, err = pkcs12.DecodeChain(receiver.P12, pkcs12.DefaultPassword); {
// // 	case err != nil:
// // 		log.Warnf("P12 decode error '%v'; ACTION: generate a new Cert", err)
// // 		return receiver.generate(inbound)
// // 	case len(ca_chain) != len(receiver.CA.CA_Chain):
// // 		log.Warnf("length of Cert/CA Chain/Key doesn't match; ACTION: generate a new Cert")
// // 		return receiver.generate(inbound)
// // 	case reflect.TypeOf(key) != reflect.TypeOf(receiver.Key):
// // 		log.Warnf("unsupported Key type; ACTION: generate a new Cert")
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	for a, b := range ca_chain {
// // 		switch {
// // 		case receiver.CA.CA_Chain[a] != b:
// // 			log.Warnf("invalid CA Chain; ACTION: generate a new Cert")
// // 			return receiver.generate(inbound)
// // 		}
// // 	}
// //
// // 	switch t.Key = key.(*ecdsa.PrivateKey); {
// // 	case interface_string("", t.Cert.PublicKey) != interface_string("", t.Key.Public()): // todo: dirty hack
// // 		// case t.Cert.PublicKey != t.Key.PublicKey:
// // 		log.Warnf("Cert/Key doesn't match; ACTION: generate a new Cert '%s' '%s'", t.Cert.PublicKey, t.Key.Public())
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	switch err = t.Cert.CheckSignatureFrom(receiver.CA.Cert); {
// // 	case err != nil:
// // 		log.Warnf("Cert's signature doesn't match with CA - '%v'; ACTION: generate a new Cert", err)
// // 		return receiver.generate(inbound)
// // 	}
// //
// // 	receiver.Cert = t.Cert
// // 	receiver.Key = t.Key
// //
// // 	receiver.DER = &_PKI_Host_Node_DER{
// // 		Cert: receiver.Cert.Raw,
// // 		Key:  nil,
// // 	}
// //
// // 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// // 	case err != nil:
// // 		log.Fatalf("can't marshal a new Key - %v", err)
// // 	}
// //
// // 	// receiver._DER_PEM()
// //
// // 	return
// // }
//
// // func (receiver *_PKI_Host_Node) generate(inbound *x509.Certificate) (status bool) { // generate cert for a Node
// // 	switch {
// // 	case inbound == nil:
// // 		log.Fatalf("no Cert data; ACTION: ignore")
// // 		// return
// // 	}
// // 	var (
// // 		err error
// // 	)
// // 	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)
// //
// // 	receiver.DER = &_PKI_Host_Node_DER{}
// //
// // 	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// // 	case err != nil:
// // 		log.Fatalf("can't generate a new Key - %v", err)
// // 	}
// //
// // 	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
// // 	case err != nil:
// // 		log.Fatalf("can't marshal a new Key - %v", err)
// // 	}
// //
// // 	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, receiver.CA.Cert, receiver.Key.Public(), receiver.CA.Key); {
// // 	case err != nil:
// // 		log.Fatalf("can't create a new Cert - %v", err)
// // 	}
// //
// // 	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
// // 	case err != nil:
// // 		log.Fatalf("can't parse a new Cert - %v", err)
// // 	}
// //
// // 	switch receiver.P12, err = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, receiver.CA.CA_Chain, pkcs12.DefaultPassword); {
// // 	case err != nil:
// // 		log.Fatalf("can't encode a new P12 - %v", err)
// // 	}
// //
// // 	// receiver._DER_PEM()
// //
// // 	return true
// // }
//

// func (receiver *_PKI) verify_old(ca *_PKI_Container, fqdn _FQDN, inbound *x509.Certificate) (outbound *_PKI_Container, is_new bool) {
// 	var (
// 		err       error
// 		container *_PKI_Container
// 		// container, is_new = receiver.get(fqdn)
// 	)
// 	// outbound, is_new = receiver.get(ca, fqdn, inbound)
//
// 	switch func() (ok bool) {
// 		switch {
// 		case interface_string("", container.Cert.PublicKey) != interface_string("", container.Key.Public()): // todo: dirty hack
// 			log.Warnf("CA Cert's signature doesn't match with CA Key's signature - '%v'; ACTION: skip.", err)
// 			return
// 		}
// 		container.CA = ca
// 		switch {
// 		case container.CA != nil:
// 			// TODO: VERY VERY VERY VERY SLOW OP
// 			switch err = container.Cert.CheckSignatureFrom(container.CA.Cert); {
// 			case err != nil:
// 				log.Warnf("PKI '%v': x509.CheckSignatureFrom error '%v'; ACTION: generate.", container.FQDN, err)
// 				return
// 			}
// 			for _, b := range container.CA.CRL.TBSCertList.RevokedCertificates {
// 				switch {
// 				case b.SerialNumber == container.SN:
// 					log.Warnf("PKI '%v': Cert is revoked; ACTION: generate.", container.FQDN)
// 					return
// 				}
// 			}
// 		}
// 		container.DER = &_PKI_DER{
// 			Cert: container.Cert.Raw,
// 			Key:  nil,
// 			CRL:  nil,
// 		}
// 		switch container.DER.Key, err = x509.MarshalPKCS8PrivateKey(container.Key); {
// 		case err != nil:
// 			log.Fatalf("PKI '%v': x509.MarshalPKCS8PrivateKey error '%v'; ACTION: report.", container.FQDN, err)
// 		}
//
// 		var (
// 			buf *bytes.Buffer
// 		)
// 		container.PEM = &_PKI_PEM{}
//
// 		buf = new(bytes.Buffer)
// 		switch err = pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: container.DER.Cert}); {
// 		case err != nil:
// 			log.Fatalf("PKI '%v': pem.Encode CERTIFICATE error '%v'; ACTION: report.", container.FQDN, err)
// 		}
// 		container.PEM.Cert = buf.Bytes()
//
// 		buf = new(bytes.Buffer)
// 		switch err = pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: container.DER.Key}); {
// 		case err != nil:
// 			log.Fatalf("PKI '%v': pem.Encode EC PRIVATE KEY error '%v'; ACTION: report.", container.FQDN, err)
// 		}
// 		container.PEM.Key = buf.Bytes()
//
// 		switch {
// 		case container.Cert.IsCA: // Cert is CA
// 			switch err = container.Cert.CheckCRLSignature(container.CRL); {
// 			case err != nil:
// 				log.Warnf("PKI '%v': CheckCRLSignature error '%v'; ACTION: generate a new CRL.", container.FQDN, err)
// 				is_new = true
// 				container.renew_CRL()
// 			}
// 			container.revoke(container.CRL.TBSCertList.RevokedCertificates)
// 			switch {
// 			case container.CRL.HasExpired(time.Now()):
// 				log.Warnf("PKI '%v': CRL HasExpired; ACTION: renew a CRL.", container.FQDN)
// 				is_new = true
// 				container.renew_CRL()
// 			}
// 			container.DER.CRL = _DER_CRL(container.CRL.TBSCertList.Raw)
//
// 			buf = new(bytes.Buffer)
// 			switch err = pem.Encode(buf, &pem.Block{Type: "X509 CRL", Bytes: container.DER.CRL}); {
// 			case err != nil:
// 				log.Fatalf("PKI '%v': pem.Encode X509 CRL error '%v'; ACTION: report.", container.FQDN, err)
// 			}
// 			container.PEM.CRL = buf.Bytes()
// 		}
//
// 		return true
// 	}(); {
// 	case true: // Cert is OK
// 		return container, is_new
// 	}
//
// 	// a new Cert is required
//
// 	switch {
// 	case inbound == nil:
// 		log.Fatalf("no Cert data; ACTION: ignore")
// 		// return
// 	}
// 	log.Infof("generating a new Cert for '%v'; ACTION: report.", inbound.Subject.CommonName)
//
// 	container.DER = &_PKI_DER{}
//
// 	switch container.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
// 	case err != nil:
// 		log.Fatalf("can't generate a new Key - %v", err)
// 	}
//
// 	switch container.DER.Key, err = x509.MarshalECPrivateKey(container.Key); {
// 	case err != nil:
// 		log.Fatalf("can't marshal a new Key - %v", err)
// 	}
//
// 	switch container.DER.Cert, err = x509.CreateCertificate(rand.Reader, inbound, container.CA.Cert, container.Key.Public(), container.CA.Key); {
// 	case err != nil:
// 		log.Fatalf("can't create a new Cert - %v", err)
// 	}
//
// 	switch container.Cert, err = x509.ParseCertificate(container.DER.Cert); {
// 	case err != nil:
// 		log.Fatalf("can't parse a new Cert - %v", err)
// 	}
//
// 	// receiver._DER_PEM()
//
// 	return container, true
// }

func (receiver *_PKI) parse_Raw(inbound ..._PKI_Raw) /*(outbound *_PKI_Container)*/ {
	switch len(inbound) {
	case 0: // nothing
		log.Warnf("PKI: no Raw data; ACTION: skip.")
		return
	}
	var (
		// outbound = new(_PKI_Container)
		outbound = &_PKI_Container{
			SN:        nil,
			FQDN:      "",
			CA:        nil,
			Raw_Chain: nil,
			Raw_CRL:   nil,
			Cert:      nil,
			Key:       nil,
			CRL:       nil,
			DER:       &_PKI_DER{},
			PEM:       &_PKI_PEM{},
			Child:     __FQDN_PKI_Container{},
		}
		err error
	)
	for _, b := range inbound {
		switch err = outbound.parse_PEM(b); {
		case err == nil:
			continue
		}
		switch err = outbound.parse_DER(b); {
		case err == nil:
			continue
		}
		switch err = outbound.parse_P12(b); {
		case err == nil:
			continue
		}
		log.Warnf("PKI: bad Raw data; ACTION: skip.")
		// return nil
	}

	switch {
	case outbound.Cert == nil || outbound.Key == nil:
		log.Warnf("PKI: no Cert/Key pair; ACTION: skip.")
		// return nil
	}

	outbound.FQDN = _FQDN(outbound.Cert.Subject.CommonName)
	outbound.SN = outbound.Cert.SerialNumber

	switch {
	case receiver.FQDN[outbound.FQDN] != nil:
		log.Warnf("PKI FQDN '%v': PKI Container already exist; ACTION: skip.", outbound.FQDN)
		// return nil
	case receiver.SN[outbound.SN] != nil:
		log.Warnf("PKI FQDN '%v', SN '%v': PKI Container already exist; ACTION: skip.", outbound.FQDN, outbound.SN)
		// return nil
	}

	i_PKI.FQDN[outbound.FQDN] = outbound
	i_PKI.SN[outbound.SN] = outbound

	// return
}
func (receiver *_PKI_Container) parse_PEM(inbound _PKI_Raw) (err error) {
	var (
		block *pem.Block
	)
	for len(inbound) != 0 {
		switch block, inbound = pem.Decode(inbound); {
		case block == nil:
			return errors.New("no PEM data left")
		}
		switch block.Type {
		case "CERTIFICATE":
			switch err = receiver.parse_DER_Cert(block.Bytes); {
			case err != nil:
				return
			}
		case "EC PRIVATE KEY":
			switch err = receiver.parse_DER_Key(block.Bytes); {
			case err != nil:
				return
			}
		case "X509 CRL":
			switch err = receiver.parse_DER_CRL(block.Bytes); {
			case err != nil:
				return
			}
		default:
			return errors.New("unknown PEM block")
		}
	}
	return
}
func (receiver *_PKI_Container) parse_DER(inbound _PKI_Raw) (err error) {
	switch err = receiver.parse_DER_Cert(_DER_Cert(inbound)); {
	case err == nil:
		return
	}
	switch err = receiver.parse_DER_Key(_DER_Key(inbound)); {
	case err == nil:
		return
	}
	switch err = receiver.parse_DER_CRL(_DER_CRL(inbound)); {
	case err == nil:
		return
	}

	return errors.New("wrong DER data")
}
func (receiver *_PKI_Container) parse_DER_Cert(inbound _DER_Cert) (err error) {
	var (
		t = new(_PKI_Container)
	)
	switch t.Raw_Chain, err = x509.ParseCertificates(inbound); {
	case err == nil:
		for _, b := range t.Raw_Chain {
			switch {
			case receiver.Cert == nil:
				receiver.Cert = b
			default:
				receiver.Raw_Chain = append(receiver.Raw_Chain, b)
			}
		}
		return
	}
	return errors.New("wrong DER Cert data")
}
func (receiver *_PKI_Container) parse_DER_Key(inbound _DER_Key) (err error) {
	var (
		t = new(_PKI_Container)
	)
	switch t.Key, err = x509.ParseECPrivateKey(inbound); {
	case err == nil:
		switch {
		case receiver.Key == nil:
			receiver.Key = t.Key
			receiver.DER.Key = inbound
			return
		default:
			log.Warnf("PKI: another Key; ACTION: ignore.")
		}
	}
	return errors.New("wrong DER Key data")
}
func (receiver *_PKI_Container) parse_DER_CRL(inbound _DER_CRL) (err error) {
	var (
		t = new(_PKI_Container)
	)
	switch t.CRL, err = x509.ParseDERCRL(inbound); {
	case err == nil:
		switch {
		case receiver.CRL == nil:
			receiver.CRL = t.CRL
			receiver.DER.CRL = inbound
			return
		default:
			log.Warnf("PKI: another CRL; ACTION: ignore.")
		}
	}
	return errors.New("wrong DER CRL data")
}
func (receiver *_PKI_Container) parse_P12(inbound _PKI_Raw) (err error) {
	var (
		t         = new(_PKI_Container)
		v_Key_any any
	)
	switch v_Key_any, t.Cert, t.Raw_Chain, err = pkcs12.DecodeChain(inbound, pkcs12.DefaultPassword); {
	case err != nil:
		return
	}
	switch {
	case reflect.TypeOf(v_Key_any) != reflect.TypeOf(&ecdsa.PrivateKey{}):
		return errors.New("wrong key type (not ecdsa.PrivateKey)")
	}
	switch {
	case receiver.Cert == nil:
		receiver.Cert = t.Cert
	default:
		log.Warnf("PKI: another Cert; ACTION: ignore.")
	}
	switch {
	case receiver.Key == nil:
		receiver.Key = v_Key_any.(*ecdsa.PrivateKey)
	default:
		log.Warnf("PKI: another Key; ACTION: ignore.")
	}
	for _, b := range t.Raw_Chain {
		receiver.Raw_Chain = append(receiver.Raw_Chain, b)
	}
	return
}

func (receiver *_PKI) verify(ca *_PKI_Container, fqdn _FQDN, inbound *x509.Certificate) (outbound *_PKI_Container, is_new bool) {
	switch {
	case receiver.FQDN[fqdn] == nil: // a new Cert
		receiver.FQDN[fqdn], is_new = &_PKI_Container{
			SN:        nil,
			FQDN:      fqdn,
			CA:        ca,
			Raw_Chain: nil,
			Raw_CRL:   nil,
			Cert:      nil,
			Key:       nil,
			CRL:       nil,
			DER:       &_PKI_DER{},
			PEM:       &_PKI_PEM{},
			Child:     __FQDN_PKI_Container{},
		}, true
		receiver.FQDN[fqdn].renew_Key()
		receiver.FQDN[fqdn].renew_Cert(inbound)
		receiver.FQDN[fqdn].renew_CRL()
		is_new = true
	default:
		receiver.FQDN[fqdn].CA = ca

		switch {
		case receiver.FQDN[fqdn].Key == nil:
			log.Warnf("PKI '%v': no Key; ACTION: generate a new Key.", receiver.FQDN[fqdn].FQDN)
			is_new = true
			receiver.FQDN[fqdn].renew_Key()
		}

		switch {
		case receiver.FQDN[fqdn].Cert == nil || interface_string("", receiver.FQDN[fqdn].Cert.PublicKey) != interface_string("", receiver.FQDN[fqdn].Key.Public()):
			log.Warnf("PKI '%v': no Cert or Cert.PublicKey != Key.Public; ACTION: renew Cert.", receiver.FQDN[fqdn].FQDN)
			is_new = true
			receiver.FQDN[fqdn].renew_Cert(inbound)
		}

		var (
			err error
		)
		switch {
		case receiver.FQDN[fqdn].Cert.IsCA: // Cert is CA
			switch err = receiver.FQDN[fqdn].Cert.CheckCRLSignature(receiver.FQDN[fqdn].CRL); {
			case err != nil:
				log.Warnf("PKI '%v': Cert.CheckCRLSignature error '%v'; ACTION: generate a new CRL.", receiver.FQDN[fqdn].FQDN, err)
				is_new = true
				receiver.FQDN[fqdn].renew_CRL()
			}
			receiver.FQDN[fqdn].revoke(receiver.FQDN[fqdn].CRL.TBSCertList.RevokedCertificates)
			switch {
			case receiver.FQDN[fqdn].CRL.HasExpired(time.Now()):
				log.Warnf("PKI '%v': CRL.HasExpired; ACTION: renew a CRL.", receiver.FQDN[fqdn].FQDN)
				is_new = true
				receiver.FQDN[fqdn].renew_CRL()
			}

		case !receiver.FQDN[fqdn].Cert.IsCA && receiver.FQDN[fqdn].CA == nil:
			log.Fatalf("PKI '%v': IsCA '%v' and CA is '%v'; ACTION: report.", receiver.FQDN, receiver.FQDN[fqdn].Cert.IsCA, receiver.FQDN[fqdn].CA)
		}

		// receiver.FQDN[fqdn].renew_CRL()
	}

	is_new = true

	switch {
	case is_new:
		receiver.FQDN[fqdn].encode()
	}

	return receiver.FQDN[fqdn], is_new
}

func (receiver *_PKI_Container) renew_Key() {
	var (
		err error
	)
	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err != nil:
		log.Fatalf("PKI '%v': ecdsa.GenerateKey error '%v'; ACTION: report.", receiver.FQDN, err)
	}
	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err != nil:
		log.Fatalf("PKI '%v': x509.MarshalECPrivateKey error '%v'; ACTION: report.", receiver.FQDN, err)
	}
}
func (receiver *_PKI_Container) renew_Cert(inbound *x509.Certificate) {
	var (
		err     error
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
		log.Fatalf("PKI '%v': x509.CreateCertificate error '%v'; ACTION: report.", receiver.FQDN, err)
	}
	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err != nil:
		log.Fatalf("PKI '%v': x509.ParseCertificate error '%v'; ACTION: report.", receiver.FQDN, err)
	}
	receiver.SN = receiver.Cert.SerialNumber

	// i_PKI.FQDN[receiver.FQDN] = receiver
	i_PKI.SN[receiver.SN] = receiver
}

func (receiver *_PKI_Container) renew_CRL() {
	switch {
	case !receiver.Cert.IsCA:
		return
	}
	var (
		err   error
		dedup = make(map[_PKI_SN]pkix.RevokedCertificate)
	)
	for _, b := range receiver.Raw_CRL {
		switch _, flag := dedup[b.SerialNumber]; {
		case !flag:
			dedup[b.SerialNumber] = b
		}
	}
	receiver.Raw_CRL = []pkix.RevokedCertificate{}
	for _, b := range dedup {
		receiver.Raw_CRL = append(receiver.Raw_CRL, b)
	}
	sort.Slice(receiver.Raw_CRL, func(i, j int) bool {
		return receiver.Raw_CRL[i].SerialNumber.Cmp(receiver.Raw_CRL[j].SerialNumber) < 0
	})

	switch receiver.DER.CRL, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		// SignatureAlgorithm:  x509.PureEd25519,
		RevokedCertificates: receiver.Raw_CRL,
		Number:              pki_crl_sn(),
		ThisUpdate:          time.Now(),
		NextUpdate:          pki_crl_expiry(),
		ExtraExtensions:     nil,
	}, receiver.Cert, receiver.Key); {
	case err != nil:
		log.Fatalf("PKI '%v': x509.CreateRevocationList error '%v'; ACTION: report.", receiver.FQDN, err)
	}
	switch receiver.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err != nil:
		log.Fatalf("PKI '%v': x509.ParseDERCRL error '%v'; ACTION: report.", receiver.FQDN, err)
	}
}
func (receiver *_PKI_Container) encode() {
	var (
		err error
		buf *bytes.Buffer
	)

	buf = new(bytes.Buffer)
	switch err = pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: receiver.DER.Key}); {
	case err != nil:
		log.Fatalf("PKI '%v': pem.Encode EC PRIVATE KEY error '%v'; ACTION: report.", receiver.FQDN, err)
	}
	receiver.PEM.Key = buf.Bytes()

	buf = new(bytes.Buffer)
	switch err = pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: receiver.Cert.Raw}); {
	case err != nil:
		log.Fatalf("PKI '%v': pem.Encode CERTIFICATE error '%v'; ACTION: report.", receiver.FQDN, err)
	}
	receiver.PEM.Cert = buf.Bytes()

	switch {
	case receiver.Cert.IsCA:
		buf = new(bytes.Buffer)
		switch err = pem.Encode(buf, &pem.Block{Type: "X509 CRL", Bytes: receiver.DER.CRL}); {
		case err != nil:
			log.Fatalf("PKI '%v': pem.Encode X509 CRL error '%v'; ACTION: report.", receiver.FQDN, err)
		}
		receiver.PEM.CRL = buf.Bytes()
	}
}

func (receiver *_PKI_Container) revoke(inbound ...[]pkix.RevokedCertificate) {
	for _, b := range inbound {
		receiver.Raw_CRL = append(receiver.Raw_CRL, b...)
	}
}

func (receiver *_PKI_PEM) bundle() (outbound _PEM_Bundle) {
	return _PEM_Bundle(receiver.Cert.String() + receiver.Key.String())
}

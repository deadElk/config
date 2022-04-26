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
		switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
		case err != nil:
			log.Fatalf("PKI '%v': x509.MarshalECPrivateKey error '%v'; ACTION: report.", receiver.FQDN, err)
		}
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

	// is_new = true

	// switch {
	// case is_new:
	receiver.FQDN[fqdn].encode()
	// }

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

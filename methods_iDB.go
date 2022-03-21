package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"

	log "github.com/sirupsen/logrus"
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

func (receiver *_PKI_CA_Node) parse_DER(cert *x509.Certificate) { // parse/create a new Node
	var (
		err, err_cert, err_key, err_crl, err_p12 error
	)
	switch {
	case receiver.DER != nil:
		receiver.Cert, err_cert = x509.ParseCertificate(receiver.DER.Cert)
		receiver.Key, err_key = x509.ParseECPrivateKey(receiver.DER.Key)
		receiver.CRL, err_crl = x509.ParseDERCRL(receiver.DER.CRL)
		// receiver.P12, err_p12 = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, nil, "")
		// receiver.P12, err_p12 = pkcs12.Encode(rand.Reader, receiver.Key, receiver.Cert, nil, pkcs12.DefaultPassword)

		switch { // double check
		case len(receiver.DER.Cert) != 0 && len(receiver.DER.Key) != 0 && len(receiver.DER.CRL) != 0 &&
			err_cert == nil && err_key == nil && err_crl == nil && err_p12 == nil &&
			receiver.Cert.PublicKey == receiver.Key.Public() &&
			receiver.Cert.SignatureAlgorithm.String() == receiver.CRL.SignatureAlgorithm.Algorithm.String() &&
			string(receiver.Cert.Signature) == string(receiver.CRL.SignatureValue.Bytes):
			return
		}
	}

	// gen new data
	switch {
	case cert == nil:
		log.Warnf("CA data invalid/absent or don't match - '%v' '%v' '%v' '%v' and no new cert data; ACTION: ignore", err_cert, err_key, err_crl, err_p12)
	}
	log.Warnf("CA data invalid/absent or don't match - '%v' '%v' '%v' '%v'; ACTION: create new using '%v'", err_cert, err_key, err_crl, err_p12, cert)

	receiver.DER = &_PKI_CA_Node_DER{}
	var (
		ca_cert   = receiver.CA.Cert
		ca_pubkey = receiver.CA.Key.Public()
		ca_SN     = inc_big_Int(receiver.CA.SN)
	)

	switch receiver.Key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); {
	case err == nil:
		log.Fatalf("can't generate new CA Key - %v", err)
	}

	switch receiver.DER.Key, err = x509.MarshalECPrivateKey(receiver.Key); {
	case err == nil:
		log.Fatalf("can't marshal new CA Key - %v", err)
	}

	switch {
	case receiver.CA == nil: // root CA, self-sign
		ca_cert = cert
		ca_pubkey = receiver.Key.Public()
		ca_SN = big.NewInt(0)
	default:
		receiver.CA_Chain = append(receiver.CA.CA_Chain, receiver.CA.Cert)
	}

	switch receiver.DER.Cert, err = x509.CreateCertificate(rand.Reader, cert, ca_cert, ca_pubkey, receiver.Key); {
	case err == nil:
		log.Fatalf("can't create new CA Cert - %v", err)
	}

	switch receiver.Cert, err = x509.ParseCertificate(receiver.DER.Cert); {
	case err == nil:
		log.Fatalf("can't parse new CA Cert - %v", err)
	}

	switch receiver.DER.CRL, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  x509.ECDSAWithSHA512,
		RevokedCertificates: nil,
		Number:              ca_SN,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions:     nil,
	}, receiver.Cert, receiver.Key); {
	case err == nil:
		log.Fatalf("can't create new CA CRL - %v", err)
	}

	switch receiver.CRL, err = x509.ParseDERCRL(receiver.DER.CRL); {
	case err == nil:
		log.Fatalf("can't parse new CA CRL - %v", err)
	}
}

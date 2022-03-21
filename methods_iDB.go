package main

import (
	"crypto/rand"
	"crypto/x509"
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
func (receiver *_PKI_CA_Node_PEM) parse_to_Node() (outbound *_PKI_CA_Node) {
	var (
		t = &_PKI_CA_Node{
			DER: receiver.parse_to_DER(),
			PEM: nil,
			P12: nil,
		}
		// err       error
	)
	switch {
	case t.DER == nil: // bad PEM
	// gen new DER and then PEM
	default:
		t.PEM = receiver
	}
	outbound = t
}
func (receiver *_PKI_CA_Node_PEM) parse_to_DER() (outbound *_PKI_CA_Node_DER) {
	var (
		t   = &_PKI_CA_Node_DER{}
		err error
	)
	switch {
	case len(receiver.CA) == 0 || len(receiver.Key) == 0:
		return
	}

	switch t.CA, err = x509.ParseCertificate(receiver.CA); {
	case err != nil:
		return
	}
	switch t.Key, err = x509.ParseECPrivateKey(receiver.Key); {
	case err != nil || t.CA.PublicKey != t.Key.PublicKey:
		return
	}

	switch {
	case len(receiver.CRL) != 0:
		switch receiver.CRL, err = x509.CreateRevocationList(rand.Reader, nil, t.CA, t.Key); {
		case err != nil:
			return
		}
	}

	switch t.CRL, err = x509.ParseCRL(receiver.CRL); {
	case err != nil || t.CA.SignatureAlgorithm.String() != t.CRL.SignatureAlgorithm.Algorithm.String() || string(t.CA.Signature) != string(t.CRL.SignatureValue.Bytes):
		return
	}
	return t

}

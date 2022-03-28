package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

type __PKI_Node []*_PKI_Node
type __PKI_CA_Node []*_PKI_CA_Node
type __BI_Any map[*big.Int]any

// type __FQDN_PKI map[_FQDN]*_PKI
type __FQDN_PKI_CA_Node map[_FQDN]*_PKI_CA_Node

// type __FQDN_PKI_Domain map[_FQDN]*_PKI_Domain
type __FQDN_PKI_Node map[_FQDN]*_PKI_Node

// PKI
// Cert_SN  *big.Int // use for all SN: Cert and CRL
// CRL_SN   *big.Int
// CA       *_PKI_CA_Node // nil for root CA or pointer to upstream CA for intermediate CA
// P12      _P12
// type _PKI struct {
// 	FQDN _FQDN
// 	CA   *_PKI_CA_Node
// 	Node __FQDN_PKI_Domain
// }
// type _PKI_Domain struct {
// 	FQDN    _FQDN
// 	CA      *_PKI_CA_Node
// 	CA_Node __FQDN_PKI_CA_Node
// 	Node    __FQDN_PKI_Node
// }
type _PKI_CA_Node struct {
	FQDN     _FQDN
	CA       *_PKI_CA_Node
	CA_Chain __Cert_Chain
	CA_Node  __FQDN_PKI_CA_Node
	Cert     *x509.Certificate
	Key      *ecdsa.PrivateKey
	CRL      *pkix.CertificateList
	DH       any
	DER      *_PKI_CA_Node_DER
	Node     __FQDN_PKI_Node
	PEM      *_PKI_CA_Node_PEM
}
type _PKI_Node struct {
	FQDN _FQDN
	CA   *_PKI_CA_Node
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	DER  *_PKI_Node_DER
	P12  _P12
	PEM  *_PKI_Node_PEM
}
type _PKI_CA_Node_DER struct {
	Cert _DER
	Key  _DER
	CRL  _DER
	DH   _DER
}
type _PKI_Node_DER struct {
	Cert _DER
	Key  _DER
}
type _PKI_CA_Node_PEM struct {
	Cert _PEM
	Key  _PEM
	CRL  _PEM
	DH   _PEM
}
type _PKI_Node_PEM struct {
	Cert _PEM
	Key  _PEM
}

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

type _DER []byte                                    //
type _P12 []byte                                    //
type _PEM []byte                                    //
type _PEM_CRL []byte                                //
type _PEM_Cert []byte                               //
type _PEM_Key []byte                                //
type _PEM_TLS_Client []byte                         //
type _PEM_TLS_Server []byte                         //
type _PKI_SN struct{ *big.Int }                     //
type __BI_Any map[*big.Int]any                      //
type __BI_Delivered map[*big.Int]*_PKI_CA_Delivered //
type __Cert_Chain []*x509.Certificate               //
type __FQDN_PKI_CA_Node map[_FQDN]*_PKI_CA_Node     //
type __FQDN_PKI_Host_Node map[_FQDN]*_PKI_Host_Node //
type __FQDN_PKI_Node map[_FQDN]*_PKI_Node           //
type __FQDN_PKI_P12 map[_FQDN]*_PKI_P12             //
type __PKI_CA_Node []*_PKI_CA_Node                  //
type __PKI_Node []*_PKI_Node                        //
type __PKI_P12 []*_PKI_P12                          //

type _PKI_CA_Node struct { //
	FQDN      _FQDN                 //
	CA        *_PKI_CA_Node         //
	CA_Chain  __Cert_Chain          //
	CA_Node   __FQDN_PKI_CA_Node    //
	Cert      *x509.Certificate     //
	Key       *ecdsa.PrivateKey     //
	CRL       *pkix.CertificateList //
	DER       *_PKI_CA_Node_DER     //
	Host_Node __FQDN_PKI_P12        //
	Node      __FQDN_PKI_P12        //
	// Delivered __BI_Delivered        //
	// Delivered_Sorted []*big.Int//
	// PEM       *_PKI_CA_Node_PEM//
}
type _PKI_CA_Delivered struct { //
	Verified bool //
	Revoked  bool //
	Status   int  //
}
type _PKI_Host_Node struct { //
	FQDN _FQDN               //
	CA   *_PKI_CA_Node       //
	Cert *x509.Certificate   //
	Key  *ecdsa.PrivateKey   //
	DER  *_PKI_Host_Node_DER //
	// PEM  *_PKI_Host_Node_PEM//
	P12 _P12 //
}
type _PKI_Node struct { //
	FQDN _FQDN             //
	CA   *_PKI_CA_Node     //
	Cert *x509.Certificate //
	Key  *ecdsa.PrivateKey //
	DER  *_PKI_Node_DER    //
	// PEM  *_PKI_Node_PEM//
	P12 _P12 //
}
type _PKI_CA_Node_DER struct { //
	Cert _DER_Cert //
	Key  _DER_Key  //
	CRL  _DER_CRL  //
}
type _PKI_Host_Node_DER struct { //
	Cert _DER_Cert //
	Key  _DER_Key  //
}
type _PKI_Node_DER struct { //
	Cert _DER_Cert //
	Key  _DER_Key  //
}
type _PKI_CA_Node_PEM struct { //
	Cert _PEM_Cert //
	Key  _PEM_Key  //
	CRL  _PEM_CRL  //
}
type _PKI_Host_Node_PEM struct { //
	Cert _PEM_Cert //
	Key  _PEM_Key  //
}
type _PKI_Node_PEM struct { //
	Cert _PEM_Cert //
	Key  _PEM_Key  //
}
type _PKI_P12 struct { //
	CA     *_PKI_CA_Node     //
	Cert   *x509.Certificate //
	DER    *_PKI_DER         //
	FQDN   _FQDN             //
	Key    *ecdsa.PrivateKey //
	P12    _P12              //
	Serial *big.Int          //
	// CA_Chain __Cert_Chain      //
	// PEM      *_PKI_PEM         //
}
type _PKI_DER struct { //
	Cert _DER_Cert //
	Key  _DER_Key  //
}
type _PKI_PEM struct { //
	Cert _PEM_Cert //
	Key  _PEM_Key  //
}

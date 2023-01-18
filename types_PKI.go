package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

type _PEM_Bundle []byte                             //
type _PEM_CRL []byte                                //
type _PEM_Cert []byte                               //
type _PEM_Key []byte                                //
type _PEM_TLS_Client []byte                         //
type _PEM_TLS_Server []byte                         //
type _PKI_Raw []byte                                //
type _PKI_SN *big.Int                               //
type __Cert_Chain []*x509.Certificate               //
type __FQDN_PKI_Container map[_FQDN]*_PKI_Container //
type __PKI_Container []*_PKI_Container              //
type __SN_PKI_Container map[_PKI_SN]*_PKI_Container //

type _PKI struct {
	FQDN __FQDN_PKI_Container //
	SN   __SN_PKI_Container   //
}
type _PKI_Container struct {
	SN        _PKI_SN                   //
	FQDN      _FQDN                     //
	CA        *_PKI_Container           //
	Raw_Chain __Cert_Chain              //
	Raw_CRL   []pkix.RevokedCertificate //
	Cert      *x509.Certificate         //
	Key       *ecdsa.PrivateKey         //
	CRL       *pkix.CertificateList     // case Is_CA == true
	DER       *_PKI_DER                 //
	PEM       *_PKI_PEM                 //
	Child     __FQDN_PKI_Container      //
}
type _PKI_DER struct {
	Cert _DER_Cert // Cert.Raw
	Key  _DER_Key  //
	CRL  _DER_CRL  // case Is_CA == true
}
type _PKI_PEM struct {
	Cert _PEM_Cert //
	Key  _PEM_Key  //
	CRL  _PEM_CRL  // case Is_CA == true
}

// type _DER []byte //
// type _P12 []byte                                    //
// type _PEM_Container []byte  //
// type __BI_Any map[_PKI_SN]any //
// // type __BI_Delivered map[*big.Int]*_PKI_CA_Delivered //
// type __FQDN_PKI_CA_Node map[_FQDN]*_PKI_CA_Node     //
// type __FQDN_PKI_Host_Node map[_FQDN]*_PKI_Host_Node //
// type __FQDN_PKI_Node map[_FQDN]*_PKI_Node           //
// type __PKI_CA_Node []*_PKI_CA_Node                  //
// type __PKI_Node []*_PKI_Node                        //
// type _PKI_CA_Node struct {
// 	CA        *_PKI_CA_Node         //
// 	CA_Chain  __Cert_Chain          //
// 	CA_Node   __FQDN_PKI_CA_Node    //
// 	CRL       *pkix.CertificateList //
// 	Cert      *x509.Certificate     //
// 	DER       *_PKI_CA_Node_DER     //
// 	FQDN      _FQDN                 //
// 	Host_Node __FQDN_PKI_Container  //
// 	Key       *ecdsa.PrivateKey     //
// 	Node      __FQDN_PKI_Container  //
// 	PEM       *_PKI_CA_Node_PEM     //
//
// 	// Key       ed25519.PrivateKey    //
//
// 	// Delivered __BI_Delivered        //
// 	// Delivered_Sorted []*big.Int//
// }
// type _PKI_CA_Delivered struct {
// 	Verified bool //
// 	Revoked  bool //
// 	Status   int  //
// }
// type _PKI_Host_Node struct {
// 	FQDN _FQDN               //
// 	CA   *_PKI_CA_Node       //
// 	Cert *x509.Certificate   //
// 	Key  *ecdsa.PrivateKey   //
// 	DER  *_PKI_Host_Node_DER //
// 	PEM  *_PKI_Host_Node_PEM //
//
// 	// Key ed25519.PrivateKey  //
// }
// type _PKI_Node struct {
// 	FQDN _FQDN             //
// 	CA   *_PKI_CA_Node     //
// 	Cert *x509.Certificate //
// 	Key  *ecdsa.PrivateKey //
// 	DER  *_PKI_Node_DER    //
// 	PEM  *_PKI_Node_PEM    //
//
// 	// Key ed25519.PrivateKey //
// }
// type _PKI_CA_Node_DER struct {
// 	Cert _DER_Cert //
// 	Key  _DER_Key  //
// 	CRL  _DER_CRL  //
// }
// type _PKI_Host_Node_DER struct {
// 	Cert _DER_Cert //
// 	Key  _DER_Key  //
// }
// type _PKI_Node_DER struct {
// 	Cert _DER_Cert //
// 	Key  _DER_Key  //
// }
// type _PKI_CA_Node_PEM struct {
// 	Cert      _PEM_Cert      //
// 	Key       _PEM_Key       //
// 	CRL       _PEM_CRL       //
// 	Container _PEM_Container //
// }
// type _PKI_Host_Node_PEM struct {
// 	Cert      _PEM_Cert      //
// 	Key       _PEM_Key       //
// 	Container _PEM_Container //
// }
// type _PKI_Node_PEM struct {
// 	Cert      _PEM_Cert      //
// 	Key       _PEM_Key       //
// 	Container _PEM_Container //
// }

package main

import (
	"math/big"
	"time"
)

func /*(receiver *_PKI_CA_Node)*/ pki_crt_expiry() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}
func /*(receiver *_PKI_CA_Node)*/ pki_crl_expiry() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}
func /*(receiver *_PKI_CA_Node)*/ pki_crt_sn() _PKI_SN {
	return big.NewInt(time.Now().UnixMicro())
}
func /*(receiver *_PKI_CA_Node)*/ pki_crl_sn() _PKI_SN {
	return big.NewInt(time.Now().UnixMicro())
}

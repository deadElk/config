package main

import (
	"math/big"
	"time"
)

// func generate_DH() (outbound *dhparam.DH) {
// 	var (
// 		err error
// 	)
// 	switch outbound, err = dhparam.Generate(1024, 5, dhparam.GeneratorCallback(nil)); {
// 	case err != nil:
// 		log.Fatalf("Error generating DH - '%v'; ACTION: report.", err)
// 	}
// 	return
// }
// func check_DH(inbound *dhparam.DH) (outbound *dhparam.DH) {
// 	switch {
// 	case inbound == nil:
// 		log.Warnf("Nil DH; ACTION: generate a new DH.")
// 		return generate_DH()
// 	}
// 	var (
// 		err    []error
// 		status bool
// 	)
// 	switch err, status = inbound.Check(); {
// 	case !status:
// 		log.Warnf("Error checking DH - '%v'; ACTION: generate a new DH.", err)
// 		return generate_DH()
// 	}
// 	return
// }

func /*(receiver *_PKI_CA_Node)*/ pki_crt_expiry() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}
func /*(receiver *_PKI_CA_Node)*/ pki_crl_expiry() time.Time {
	return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
}
func /*(receiver *_PKI_CA_Node)*/ pki_crt_sn() *big.Int {
	return big.NewInt(time.Now().UnixMicro())
}
func /*(receiver *_PKI_CA_Node)*/ pki_crl_sn() *big.Int {
	return big.NewInt(time.Now().UnixMicro())
}

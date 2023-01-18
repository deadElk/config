package main

import (
	"encoding/hex"
	"strconv"
	"strings"
)

func (receiver _hash_ID) String() string {
	return strings.ToUpper(hex.EncodeToString(receiver[:]))
}
func (receiver _hash224_ID) String() string {
	return hex.EncodeToString(receiver[:])
}
func (receiver _DN) String() string {
	return string(receiver)
}
func (receiver _ID) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _IDName) String() string {
	return string(receiver)
}
func (receiver _Inet_ASN) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _W) String() string {
	return string(receiver)
}
func (receiver _Communication) String() string {
	return string(receiver)
}
func (receiver _Content) String() string {
	return string(receiver)
}
func (receiver _S) String() string {
	return string(receiver)
}
func (receiver _Description) String() string {
	return string(receiver)
}
func (receiver _FQDN) String() string {
	return string(receiver)
}
func (receiver _Mask) String() string {
	return string(receiver)
}
func (receiver _Name) String() string {
	return string(receiver)
}
func (receiver _Link_Name) String() string {
	return string(receiver)
}
func (receiver _File_Name) String() string {
	return string(receiver)
}
func (receiver _Dir_Name) String() string {
	return string(receiver)
}
func (receiver _DER_Cert) String() string {
	return string(receiver)
}
func (receiver _DER_Key) String() string {
	return string(receiver)
}
func (receiver _DER_CRL) String() string {
	return string(receiver)
}
func (receiver _DER_TLS_Server) String() string {
	return string(receiver)
}
func (receiver _DER_TLS_Client) String() string {
	return string(receiver)
}
func (receiver _PEM_Bundle) String() string {
	return string(receiver)
}
func (receiver _PEM_Cert) String() string {
	return string(receiver)
}
func (receiver _PEM_Key) String() string {
	return string(receiver)
}
func (receiver _PEM_CRL) String() string {
	return string(receiver)
}
func (receiver _PKI_Raw) String() string {
	return string(receiver)
}
func (receiver _PEM_TLS_Server) String() string {
	return string(receiver)
}
func (receiver _PEM_TLS_Client) String() string {
	return string(receiver)
}
func (receiver _PName) String() string {
	return string(receiver)
}
func (receiver _INet_Port) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _INet_Protocol) String() string {
	return string(receiver)
}
func (receiver _INet_Routing) String() string { return strconv.FormatUint(uint64(receiver), 10) }
func (receiver _Secret) String() string       { return string(receiver) }
func (receiver _Service) String() string {
	return string(receiver)
}
func (receiver _Type) String() string {
	return string(receiver)
}
func (receiver _VI_ID) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _VI_Conn_ID) String() string {
	return strconv.FormatUint(uint64(receiver), 10)
}
func (receiver _INet_IPPrefix) String() string {
	return string(parse_interface(receiver.MarshalText()).([]byte))
}
func (receiver _INet_IPAddr) String() string {
	return string(parse_interface(receiver.MarshalText()).([]byte))
}
func (receiver _INet_URL) String() string {
	return receiver.String()
}

// func (receiver _DER) String() string {
// 	return string(receiver)
// }
// func (receiver _P12) String() string {
// 	return string(receiver)
// }

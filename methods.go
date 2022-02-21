package main

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (inbound _ASN) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _ASN) _Sanitize() _ASN_PName {
	var (
		interim = "0000000000" + strconv.FormatUint(uint64(inbound), 10)
	)
	return _ASN_PName(interim[len(interim)-10:])
}
func (inbound _ASN_PName) String() string {
	return string(inbound)
}
func (inbound _VI_ID) _Sanitize() _VI_ID_PName {
	var (
		interim = "00000" + strconv.FormatUint(uint64(inbound), 10)
	)
	return _VI_ID_PName(interim[len(interim)-5:])
}
func (inbound _VI_ID) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _VI_ID_PName) String() string {
	return string(inbound)
}
func (inbound _IF_Communication) _Sanitize(mode _IF_Mode) (outbound _IF_Communication) {
	switch mode {
	case _if_mode_vi:
		switch inbound {
		case _if_comm_ptmp, _if_comm_ptp:
			return inbound
		case "":
			return _default_vi_comm
		default:
			outbound = _default_vi_comm
		}
	case _if_mode_link:
		switch inbound {
		case _if_comm_ptmp, _if_comm_ptp:
			return inbound
		case "":
			return _default_if_comm
		default:
			outbound = _default_if_comm
		}
	}
	log.Warnf("unknow IF Communication type '%v'; ACTION: use '%v'.", inbound, outbound)
	return
}
func (inbound _Description) _Sanitize(default_description _Description) _Description {
	switch len(inbound) == 0 {
	case true:
		return default_description
	}
	return inbound
}
func (inbound _GT_Content) _Sanitize() (outbound _GT_Content) {
	for _, value := range strings.Split(string(inbound), "\n") {
		outbound += _GT_Content(strings.TrimSpace(value) + "\n")
	}
	return
}
func (inbound _RI_Name) String() string {
	return string(inbound)
}
func (inbound _RI_Name) _Sanitize(decline ..._RI_Name) (outbound _RI_Name) {
	outbound = _juniper_default_RI
	switch len(inbound) == 0 || inbound == _juniper_default_RI {
	case true:
		return
	}
	for _, interim := range decline {
		switch inbound == interim {
		case true:
			return
		}
	}
	return inbound
}
func (inbound _IF_Name) String() string {
	return string(inbound)
}
func (inbound _IFM_Name) String() string {
	return string(inbound)
}
func (inbound _GW_Type) String() string {
	return string(inbound)
}
func (inbound _GT_Name) String() string {
	return string(inbound)
}
func (inbound _GT_Content) String() string {
	return string(inbound)
}
func (inbound _Policy) _Sanitize() _Policy {
	switch len(inbound) == 0 {
	case true:
		return _default_policy
	}
	switch inbound {
	case _policy_restrictive, _policy_permissive:
		return inbound
	default:
		log.Warnf("unknow security policy '%v'; ACTION: use default '%v'.", inbound, _default_policy)
		return _default_policy
	}
}
func (inbound _Policy) String() string {
	return string(inbound)
}
func (inbound _Secret) _Sanitize(length uint, message ...string) _Secret {
	switch len(inbound) >= int(length) {
	case true:
		return inbound
	}
	var (
		ret = make([]byte, length)
	)
	for i := 0; i < int(length); i++ {
		switch next, err := rand.Int(rand.Reader, big.NewInt(int64(len(_passwd)))); err == nil && next != nil {
		case true:
			ret[i] = _passwd[next.Int64()]
		default:
			log.Panicf("rand.Int error: %#v", err)
		}
	}
	switch len(message) > 0 {
	case true:
		log.Warnf("%v; ACTION: new value is '%v'.", message[0], string(ret))
	}
	return _Secret(ret)
}
func (inbound _Secret) String() string {
	return string(inbound)
}
func (inbound _VI_Type) String() string {
	return string(inbound)
}
func (inbound _VI_Type) _Sanitize() _VI_Type {
	switch len(inbound) == 0 {
	case true:
		return _default_vi
	}
	switch inbound {
	case _vi_ti:
		return inbound
	case _vi_gr, _vi_lt:
		log.Errorf("unsupported VI type '%v'; ACTION: use default '%v'.", inbound, _default_vi)
		return _default_vi
	default:
		log.Warnf("unknow VI type '%v'; ACTION: use default '%v'.", inbound, _default_vi)
		return _default_vi
	}
}
func (inbound _Service) String() string {
	return string(inbound)
}
func (inbound _Protocol) String() string {
	return string(inbound)
}
func (inbound _AB_Name) String() string {
	return string(inbound)
}
func (inbound _FQDN) String() string {
	return string(inbound)
}

package main

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (inbound _Action) String() string {
	return string(inbound)
}
func (inbound _Type) String() string {
	return string(inbound)
}
func (inbound _Service) String() string {
	return string(inbound)
}
func (inbound _Protocol) String() string {
	return string(inbound)
}

func (inbound _ASN) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _ASN) _PName() _PName {
	var (
		interim = "0000000000" + strconv.FormatUint(uint64(inbound), 10)
	)
	return _PName(interim[len(interim)-10:])
}
func (inbound _VI_ID) _PName() _PName {
	var (
		interim = "00000" + strconv.FormatUint(uint64(inbound), 10)
	)
	return _PName(interim[len(interim)-5:])
}
func (inbound _VI_ID) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _Default) String() string {
	return string(inbound)
}
func (inbound _Name) String() string {
	return string(inbound)
}
func (inbound _Mask) String() string {
	return string(inbound)
}
func (inbound _Communication) _Sanitize(mode _Mode) (outbound _Communication) {
	switch mode {
	case _if_mode_vi:
		switch inbound {
		case _if_comm_ptmp, _if_comm_ptp:
			return inbound
		case "":
			return _vi_comm_
		default:
			outbound = _vi_comm_
		}
	case _if_mode_link:
		switch inbound {
		case _if_comm_ptmp, _if_comm_ptp:
			return inbound
		case "":
			return _if_comm_
		default:
			outbound = _if_comm_
		}
	}
	log.Warnf("unknown IF Communication type '%v'; ACTION: use '%v'.", inbound, outbound)
	return
}
func (inbound _Description) _Validate(default_description _Description) _Description {
	switch len(inbound) == 0 {
	case true:
		return default_description
	}
	return inbound
}
func (inbound _Content) _Sanitize() (outbound _Content) {
	for _, value := range strings.Split(string(inbound), "\n") {
		outbound += _Content(strings.TrimSpace(value) + "\n")
	}
	return
}
func (inbound _Name) _Validate(decline ..._Name) (outbound _Name) {
	outbound = _juniper_RI_
	switch len(inbound) == 0 || inbound == _juniper_RI_ {
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
func (inbound _Content) String() string {
	return string(inbound)
}
func (inbound _Secret) _Sanitize(length uint, message ...string) _Secret {
	switch len(inbound) >= int(length) {
	case true:
		return inbound
	}
	var (
		interim = make([]byte, length)
	)
	for i := 0; i < int(length); i++ {
		switch next, err := rand.Int(rand.Reader, big.NewInt(int64(len(_passwd)))); err == nil && next != nil {
		case true:
			interim[i] = _passwd[next.Int64()]
		default:
			log.Panicf("rand.Int error: %#v", err)
		}
	}
	switch len(message) > 0 {
	case true:
		log.Warnf("%v; ACTION: new value is '%v'.", message[0], string(interim))
	}
	return _Secret(interim)
}
func (inbound _Secret) String() string {
	return string(inbound)
}

func (inbound _Type) _VI_Sanitize() _Type {
	switch inbound {
	case _Type_st, "":
		return inbound
	case _Type_gr, _Type_lt:
		log.Errorf("unsupported VI type '%v'; ACTION: use default '%v'.", inbound, _Type_st)
		return _Type_st
	default:
		log.Warnf("unknown VI type '%v'; ACTION: use default '%v'.", inbound, _Type_st)
		return _Type_st
	}
}
func (inbound _PName) String() string {
	return string(inbound)
}
func (inbound _Mode) String() string {
	return string(inbound)
}
func (inbound _FQDN) String() string {
	return string(inbound)
}
func (inbound _FQDN) _Name() _Name {
	return _Name(inbound.String())
}
func (inbound _Host_Inbound_Traffic) _Defaults() _Host_Inbound_Traffic {
	return _Host_Inbound_Traffic{
		Services: map[_Service]bool{
			_service_ping:       true,
			_service_ssh:        true,
			_service_traceroute: true,
		},
		Protocols: map[_Protocol]bool{},
	}
}
func (inbound _Action) _SP_Validate() _Action {
	switch inbound {
	case _Action_permit_all, _Action_deny_all:
		return inbound
	case "":
		return _Action_permit_all
	}
	log.Warnf("unknown SP default action '%v'; ACTION: use default '%v'.", inbound, _Action_permit_all)
	return _Action_permit_all
}

func (inbound _IPPrefix) String() string {
	switch inbound.IsValid() {
	case false:
		return ""
	}
	return inbound.String()
}
func (inbound _IPAddr) String() string {
	switch inbound.IsValid() {
	case false:
		return ""
	}
	return inbound.StringExpanded()
}

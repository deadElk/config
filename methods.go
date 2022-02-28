package main

import (
	"crypto/rand"
	"math/big"

	log "github.com/sirupsen/logrus"
)

func (inbound _Description) _Validate(default_description _Description) _Description {
	switch len(inbound) == 0 {
	case true:
		return default_description
	}
	return inbound
}
func (inbound *_Secret) _Validate(length uint, message ...string) _Secret {
	switch len(*inbound) >= int(length) {
	case true:
		return *inbound
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
func (inbound _FQDN) _Name() _Name {
	return _Name(inbound.String())
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

func (inbound _Name) _Validate_RI(decline ..._Name) (outbound _Name) {
	outbound = _Defaults[_RI].(_Name)
	switch len(inbound) == 0 || inbound == outbound {
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

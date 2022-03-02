package main

import (
	"crypto/rand"
	"math/big"

	log "github.com/sirupsen/logrus"
)

func (inbound *_Secret) validate(length uint, message ...string) _Secret {
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
func (inbound *_Name) validate_RI(decline ..._Name) (outbound _Name) {
	outbound = _Defaults[_RI].(_Name)
	switch len(*inbound) == 0 || *inbound == outbound {
	case true:
		return
	}
	for _, interim := range decline {
		switch *inbound == interim {
		case true:
			return
		}
	}
	return *inbound
}

func (inbound *i_Peer) link_AB(name ..._Name) {
	for _, value := range name {
		switch i_ab[value] == nil {
		case true:
			continue
		}
		inbound.AB[value] = i_ab[value]
	}
}
func (inbound *i_Peer) link_JA(name ..._Name) {
	for _, value := range name {
		switch i_ja[value] == nil {
		case true:
			continue
		}
		inbound.JA[value] = i_ja[value]
	}
}
func (inbound *i_Peer) link_PL(name ..._Name) {
	for _, value := range name {
		switch i_pl[value] == nil {
		case true:
			continue
		}
		inbound.PL[value] = i_pl[value]
	}
}
func (inbound *i_Peer) link_PS(name ..._Name) {
	for _, value := range name {
		switch i_ps[value] == nil {
		case true:
			continue
		}
		inbound.PS[value] = i_ps[value]
	}
}

func (inbound *Host_Inbound_Traffic_List) parse(enable ...interface{}) (outbound Host_Inbound_Traffic_List) {
	switch inbound == nil {
	case false:
		outbound = *inbound
	default:
		outbound = Host_Inbound_Traffic_List{
			Services:       map[_Service]bool{},
			Protocols:      map[_Protocol]bool{},
			GT_Action_List: GT_Action_List{GT_Action: "host-inbound-traffic "},
		}
	}
	for _, b := range enable {
		switch value := b.(type) {
		case _Service:
			outbound.Services[value] = true
		case _Protocol:
			outbound.Protocols[value] = true
		}
	}
	return
}

func (inbound *_Name) validate_AB(peer *cDB_Peer, v_Peer *i_Peer, inbound_type map[_Type]bool) (outbound _Name) {
	switch _, flag := i_ab[*inbound]; {
	case len(*inbound) != 0 && !flag && *inbound != "any":
		log.Warnf("Peer '%v', unknown AB '%v'; ACTION: skip.", peer.ASN, *inbound)
		return
	case len(*inbound) != 0 && flag && *inbound != "any":
		v_Peer.link_AB(*inbound)
	}
	return
}

package main

import (
	"crypto/rand"
	"math/big"

	log "github.com/sirupsen/logrus"
)

func (inbound *_Secret) validate(length uint, message ...string) _Secret {
	switch {
	case len(*inbound) >= int(length):
		return *inbound
	}
	var (
		interim = make([]byte, length)
	)
	for i := 0; i < int(length); i++ {
		switch next, err := rand.Int(rand.Reader, big.NewInt(int64(len(_passwd)))); {
		case err == nil && next != nil:
			interim[i] = _passwd[next.Int64()]
		default:
			log.Panicf("rand.Int error: %#v", err)
		}
	}
	switch {
	case len(message) > 0:
		log.Warnf("%v; ACTION: new value is '%v'.", message[0], string(interim))
	}
	return _Secret(interim)
}
func (inbound *_Name) validate_RI(decline ..._Name) (outbound _Name) {
	outbound = _Settings[_RI].(_Name)
	switch {
	case len(*inbound) == 0 || *inbound == outbound:
		return
	}
	for _, interim := range decline {
		switch {
		case *inbound == interim:
			return
		}
	}
	return *inbound
}

func (inbound *i_Peer) link_AB(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ab[value] == nil:
			continue
		}
		inbound.AB[value] = i_ab[value]
	}
}
func (inbound *i_Peer) link_JA(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ja[value] == nil:
			continue
		}
		inbound.JA[value] = i_ja[value]
	}
}
func (inbound *i_Peer) link_PL(name ..._Name) {
	for _, value := range name {
		switch {
		case i_pl[value] == nil:
			continue
		}
		inbound.PL[value] = i_pl[value]
	}
}
func (inbound *i_Peer) link_PS(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ps[value] == nil:
			continue
		}
		inbound.PS[value] = i_ps[value]
	}
}

func (inbound *_Host_Inbound_Traffic_List) parse(enable ...interface{}) (outbound _Host_Inbound_Traffic_List) {
	switch {
	case inbound != nil:
		outbound = *inbound
	default:
		outbound = _Host_Inbound_Traffic_List{
			Services:  map[_Service]bool{},
			Protocols: map[_Protocol]bool{},
			GT_Action: _W_host__inbound__traffic.String(),
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

func (inbound *_Name) action_AB(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := i_ab[*inbound]; {
	case len(*inbound) == 0:
		return
	case !flag && *inbound != _Name_any:
		log.Warnf("Peer '%v', unknown AB '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
		return
	case flag && *inbound != _Name_any:
		v_Peer.link_AB(*inbound)
	}

	switch {

	case inbound_type == _Type_exact && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address, inbound)
	case inbound_type == _Type_global && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address__name, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address__name, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address__name, inbound)

	case inbound_type == _Type_exact && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address, inbound)
	case inbound_type == _Type_global && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address__name, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address__name, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address__name, inbound)

	case inbound_type == _Type_exact && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_source__address, inbound)
	case inbound_type == _Type_global && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_source__address, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_source__address__name, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_destination__address__name, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_prefix__name, inbound)

	case v_Peer != nil:
		log.Warnf("Peer '%v', AB '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
	}

	return
}
func (inbound *_Name) action_Pool(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*inbound) == 0:
		return
	}
	return strings_join(" ", _W_pool, inbound)
}
func (inbound *_Protocol) action_Protocol(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*inbound) == 0:
		return
	}
	return strings_join(" ", _W_protocol, inbound)
}
func (inbound *_Type) action_Route_Type(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*inbound) == 0:
		return
	}
	return strings_join(" ", _W_route__type, inbound)
}
func (inbound *_Name) action_RI(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*inbound) == 0:
		return
	case v_Peer != nil:
		switch _, flag := v_Peer.RI[*inbound]; {
		case !flag && *inbound != _Settings[_host_RI].(_Name):
			log.Warnf("Peer '%v', unknown RI '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
			return
		}
	}

	switch {

	case inbound_type == _Type_source && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from, _W_routing__instance, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to, _W_routing__instance, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_pool:
		outbound = strings_join(" ", _W_routing__instance, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, inbound)

	case inbound_type == _Type_destination && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from, _W_routing__instance, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to, _W_routing__instance, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_pool:
		outbound = strings_join(" ", _W_routing__instance, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, inbound)

	case inbound_type == _Type_static && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from, _W_routing__instance, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to, _W_routing__instance, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_pool:
		outbound = strings_join(" ", _W_routing__instance, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, inbound)

	case inbound_type == _Type_firewall && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from, _W_routing__instance, inbound)
	case inbound_type == _Type_firewall && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to, _W_routing__instance, inbound)
	case inbound_type == _Type_firewall && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, inbound)

	case inbound_type == _Type_policy__statement:
		outbound = strings_join(" ", _W_routing__instance, inbound)

	case v_Peer != nil:
		log.Warnf("Peer '%v', RI '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
	}
	return
}
func (inbound *_Name) action_SZ(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := v_Peer.SZ[*inbound]; {
	case len(*inbound) == 0:
		return
	case !flag && *inbound != _Name_any && *inbound != _Settings[_host_RI].(_Name):
		log.Warnf("Peer '%v', unknown SZ '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
		return
	}

	switch {

	case inbound_type == _Type_source && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from___zone, inbound)
	case inbound_type == _Type_source && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to___zone, inbound)

	case inbound_type == _Type_destination && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from___zone, inbound)
	case inbound_type == _Type_destination && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to___zone, inbound)

	case inbound_type == _Type_static && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from__zone, inbound)
	case inbound_type == _Type_static && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to__zone, inbound)

	case inbound_type == _Type_exact && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from__zone, inbound)
	case inbound_type == _Type_exact && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to__zone, inbound)

	case inbound_type == _Type_global && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from__zone, inbound)
	case inbound_type == _Type_global && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_to__zone, inbound)

	case v_Peer != nil:
		log.Warnf("Peer '%v', SZ '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
	}

	return
}
func (inbound *_Name) action_IF(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := v_Peer.IF_2_RI[*inbound]; {
	case len(*inbound) == 0:
		return
	case !flag:
		log.Warnf("Peer '%v', unknown IF '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
		return
	}
	return strings_join(" ", _W_interface, inbound)
}
func (inbound *_Name) action_PL(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := i_pl[*inbound]; {
	case len(*inbound) == 0:
		return
	case !flag && v_Peer != nil:
		log.Warnf("Peer '%v', unknown PL '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
		return
	}

	switch {

	case inbound_type == _Type_firewall && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_from, _W_source__prefix__list, inbound)
	case inbound_type == _Type_firewall && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_from, _W_destination__prefix__list, inbound)

	case inbound_type == _Type_policy__statement:
		outbound = strings_join(" ", _W_prefix__list__filter, inbound)

	case v_Peer != nil:
		log.Warnf("Peer '%v', PL '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *inbound, inbound_type, inbound_direction)
	}

	return
}

func (inbound *_Name) next_ID() (outbound _Name) {
	switch {
	case *inbound == _next_IDName || len(*inbound) == 0:
		outbound = _Name(strings_join("", _Name_ID, pad(next_ID, 10)))
		next_ID++
		return
	}
	return *inbound
}
func (inbound *_ID) next_ID() (outbound _ID) {
	switch {
	case *inbound == _next_ID || *inbound == 0:
		outbound = next_ID
		next_ID++
		return
	}
	return *inbound
}

func (inbound *_W) validate(peer *cDB_Peer, v_Peer *i_Peer) (outbound _W) {
	outbound = c_RO_GW[*inbound]
	switch {
	case len(*inbound) == 0:
		return
	case len(outbound) == 0:
		log.Warnf("Peer '%v', unknown _W '%v'; ACTION: return '%v'.", v_Peer.ASN, *inbound, outbound)
		return
	}
	return
}

package main

import (
	"crypto/rand"
	"math/big"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (receiver *_Secret) validate(length uint, message string) _Secret {
	switch {
	case len(*receiver) >= int(length):
		return *receiver
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
		log.Warnf("%v: _Secret is too weak; ACTION: use '%v'.", message, string(interim))
	}
	return _Secret(interim)
}
func (receiver *_Name) validate_RI(v_Peer *i_Peer, decline ..._Name) (outbound _Name) {
	outbound = v_Peer.Group.Master_RI
	switch {
	case len(*receiver) == 0 || *receiver == outbound:
		return
	}
	for _, interim := range decline {
		switch {
		case *receiver == interim:
			return
		}
	}
	return *receiver
}

func (receiver *_Host_Inbound_Traffic_List) parse(enable ...interface{}) (outbound _Host_Inbound_Traffic_List) {
	switch {
	case receiver != nil:
		outbound = *receiver
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

func (receiver *_Name) action_AB(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := i_ab[*receiver]; {
	case len(*receiver) == 0:
		return
	case !flag && *receiver != _Name_any:
		log.Warnf("Peer '%v', unknown AB '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
		return
	case flag && *receiver != _Name_any:
		v_Peer.link_AB(*receiver)
	}

	switch {

	case receiver_type == _Type_exact && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address__name, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address__name, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_source__address__name, receiver)

	case receiver_type == _Type_exact && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address__name, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address__name, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__address__name, receiver)

	case receiver_type == _Type_exact && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_source__address, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_source__address, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_source__address__name, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_destination__address__name, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_prefix__name, receiver)

	case v_Peer != nil:
		log.Warnf("Peer '%v', AB '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
	}

	return
}
func (receiver *_Name) action_Pool(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*receiver) == 0:
		return
	}
	return strings_join(" ", _W_pool, receiver)
}
func (receiver *_Protocol) action(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*receiver) == 0:
		return
	}
	return strings_join(" ", _W_protocol, receiver)
}
func (receiver *_Type) action_Route_Type(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*receiver) == 0:
		return
	}
	return strings_join(" ", _W_route__type, receiver)
}
func (receiver *_Name) action_RI(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*receiver) == 0:
		return
	case v_Peer != nil:
		switch _, flag := v_Peer.RI[*receiver]; {
		case !flag && *receiver != v_Peer.Group.Host_RI:
			log.Warnf("Peer '%v', unknown RI '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
			return
		}
	}

	switch {

	case receiver_type == _Type_source && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_pool:
		outbound = strings_join(" ", _W_routing__instance, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_destination && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_pool:
		outbound = strings_join(" ", _W_routing__instance, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_static && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_pool:
		outbound = strings_join(" ", _W_routing__instance, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_firewall && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_firewall && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_firewall && receiver_direction == _Type_then:
		outbound = strings_join(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_policy__statement:
		outbound = strings_join(" ", _W_routing__instance, receiver)

	case v_Peer != nil:
		log.Warnf("Peer '%v', RI '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
	}
	return
}
func (receiver *_Name) action_SZ(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := v_Peer.SZ[*receiver]; {
	case len(*receiver) == 0:
		return
	case !flag && *receiver != _Name_any && *receiver != v_Peer.Group.Host_RI:
		log.Warnf("Peer '%v', unknown SZ '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
		return
	}

	switch {

	case receiver_type == _Type_source && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___zone, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to___zone, receiver)

	case receiver_type == _Type_destination && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___zone, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to___zone, receiver)

	case receiver_type == _Type_static && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from__zone, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to__zone, receiver)

	case receiver_type == _Type_exact && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from__zone, receiver)
	case receiver_type == _Type_exact && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to__zone, receiver)

	case receiver_type == _Type_global && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from__zone, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_to__zone, receiver)

	case v_Peer != nil:
		log.Warnf("Peer '%v', SZ '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
	}

	return
}
func (receiver *_Name) action_IF(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := v_Peer.IF_2_RI[*receiver]; {
	case len(*receiver) == 0:
		return
	case !flag:
		log.Warnf("Peer '%v', unknown IF '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
		return
	}
	return strings_join(" ", _W_interface, receiver)
}
func (receiver *_Name) action_PL(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch _, flag := i_pl[*receiver]; {
	case len(*receiver) == 0:
		return
	case !flag && v_Peer != nil:
		log.Warnf("Peer '%v', unknown PL '%v', type '%v', subtype '%v'; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
		return
	}

	switch {

	case receiver_type == _Type_firewall && receiver_direction == _Type_from:
		outbound = strings_join(" ", _W_from___source__prefix__list, receiver)
	case receiver_type == _Type_firewall && receiver_direction == _Type_to:
		outbound = strings_join(" ", _W_from___destination__prefix__list, receiver)

	case receiver_type == _Type_policy__statement:
		outbound = strings_join(" ", _W_prefix__list__filter, receiver)

	case v_Peer != nil:
		log.Warnf("Peer '%v', PL '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
	}

	return
}

func (receiver *_Name) next_ID() (outbound _Name) {
	switch {
	case *receiver == _next_IDName || len(*receiver) == 0:
		outbound = _Name(strings_join("", _Name_ID, pad(next_ID, 10)))
		next_ID++
		return
	}
	return *receiver
}
func (receiver *_ID) next_ID() (outbound _ID) {
	switch {
	case *receiver == _next_ID || *receiver == 0:
		outbound = next_ID
		next_ID++
		return
	}
	return *receiver
}

func (receiver *_W) validate_RO_GW_Action(peer *cDB_Peer, v_Peer *i_Peer) (outbound _W) {
	outbound = c_RO_GW_Action[*receiver]
	switch {
	case len(*receiver) == 0:
		return
	case len(outbound) == 0:
		log.Warnf("Peer '%v', unknown _W '%v'; ACTION: return '%v'.", v_Peer.ASN, *receiver, outbound)
		return
	}
	return
}

func (receiver *_Content) trim_space() _Content {
	var (
		interim string
	)
	// for _, value := range strings.Split(string(*receiver), "\n") {
	for _, value := range strings.Split(convert_2_string("", receiver), "\n") {
		interim += strings.TrimSpace(value) + "\n"
	}
	return _Content(interim)
}

// func (receiver *_FQDN) parse_Domain_Name() (outbound _FQDN) {
// 	switch {
// 	case len(*receiver) == 0:
// 		return
// 	}
// 	return *receiver
// }

func (receiver *_Communication) parse(_comm _Communication) _Communication {
	switch {
	case *receiver == _Communication_ptp || *receiver == _Communication_ptmp:
		return *receiver
	case len(*receiver) != 0:
		log.Warnf("invalid interface Communication type '%v'; ACTION: use '%v'.", *receiver, _comm)
		fallthrough
	default:
		return _comm
	}
}

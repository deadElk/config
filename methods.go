package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net/netip"
	"sort"
	"strings"
	"text/template"

	log "github.com/sirupsen/logrus"
)

func (receiver *_Secret) validate(length uint, message string) _Secret {
	switch {
	case len(*receiver) >= int(length):
		return *receiver
	}
	var (
		interim = make([]byte, length, length)
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
func (receiver *_Name) validate_RI(v_Peer *i_Peer, default_RI _Name, decline ..._Name) (outbound _Name) {
	switch {
	case len(default_RI) == 0:
		outbound = v_Peer.Group.Master_RI
	default:
		outbound = default_RI
	}
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

func (receiver *_Host_Inbound_Traffic_List) parse(enable ...any) (outbound _Host_Inbound_Traffic_List) {
	switch {
	case receiver != nil:
		outbound = *receiver
	default:
		outbound = _Host_Inbound_Traffic_List{
			Services:  map[_Service]bool{},
			Protocols: map[_INet_Protocol]bool{},
			GT_Action: _W_host__inbound__traffic.String(),
		}
	}
	for _, b := range enable {
		switch value := b.(type) {
		case _Service:
			outbound.Services[value] = true
		case _INet_Protocol:
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
		outbound = join_string(" ", _W_source__address, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_source__address, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_source__address__name, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_source__address__name, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_source__address__name, receiver)

	case receiver_type == _Type_exact && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_destination__address, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_destination__address, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_destination__address__name, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_destination__address__name, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_destination__address__name, receiver)

	case receiver_type == _Type_exact && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_source__address, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_source__address, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_source__address__name, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_destination__address__name, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_prefix__name, receiver)

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
	return join_string(" ", _W_pool, receiver)
}
func (receiver *_INet_Protocol) action(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*receiver) == 0:
		return
	}
	return join_string(" ", _W_protocol, receiver)
}
func (receiver *_Type) action_Route_Type(peer *cDB_Peer, v_Peer *i_Peer, receiver_type _Type, receiver_direction _Type) (outbound string /* , ok bool */) {
	switch {
	case len(*receiver) == 0:
		return
	}
	return join_string(" ", _W_route__type, receiver)
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
		outbound = join_string(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_pool:
		outbound = join_string(" ", _W_routing__instance, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_destination && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_pool:
		outbound = join_string(" ", _W_routing__instance, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_static && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_pool:
		outbound = join_string(" ", _W_routing__instance, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_firewall && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from___routing__instance, receiver)
	case receiver_type == _Type_firewall && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to___routing__instance, receiver)
	case receiver_type == _Type_firewall && receiver_direction == _Type_then:
		outbound = join_string(" ", _W_routing__instance, receiver)

	case receiver_type == _Type_policy_statement:
		outbound = join_string(" ", _W_routing__instance, receiver)

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
		outbound = join_string(" ", _W_from___zone, receiver)
	case receiver_type == _Type_source && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to___zone, receiver)

	case receiver_type == _Type_destination && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from___zone, receiver)
	case receiver_type == _Type_destination && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to___zone, receiver)

	case receiver_type == _Type_static && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from__zone, receiver)
	case receiver_type == _Type_static && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to__zone, receiver)

	case receiver_type == _Type_exact && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from__zone, receiver)
	case receiver_type == _Type_exact && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to__zone, receiver)

	case receiver_type == _Type_global && receiver_direction == _Type_from:
		outbound = join_string(" ", _W_from__zone, receiver)
	case receiver_type == _Type_global && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_to__zone, receiver)

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
	return join_string(" ", _W_interface, receiver)
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
		outbound = join_string(" ", _W_from___source__prefix__list, receiver)
	case receiver_type == _Type_firewall && receiver_direction == _Type_to:
		outbound = join_string(" ", _W_from___destination__prefix__list, receiver)

	case receiver_type == _Type_policy_statement:
		outbound = join_string(" ", _W_prefix__list__filter, receiver)

	case v_Peer != nil:
		log.Warnf("Peer '%v', PL '%v', type '%v', subtype '%v', unknown operation; ACTION: return ''.", v_Peer.ASN, *receiver, receiver_type, receiver_direction)
	}

	return
}

func (receiver *_Name) next_ID() (outbound _Name) {
	switch {
	case *receiver == _next_IDName || len(*receiver) == 0:
		outbound = _Name(join_string("", _Name_ID, pad_string(next_ID, 10)))
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

func (receiver *_Content) trim_space() {
	var (
		delimiter = "\n"
		value     = strings.Split(receiver.String(), delimiter)
		inbounds  = len(value) - 1
		buffer    = new(bytes.Buffer)
	)
	for a, b := range value {
		buffer.WriteString(strings.TrimSpace(b))
		switch {
		case a < inbounds:
			buffer.WriteString(delimiter)
		}
	}
	*receiver = buffer.Bytes()
}

func (receiver *_Communication) parse(default_Communication _Communication) _Communication {
	switch {
	case *receiver == _Communication_ptp || *receiver == _Communication_ptmp:
		return *receiver
	case len(*receiver) != 0:
		log.Warnf("invalid interface Communication type '%v'; ACTION: use '%v'.", *receiver, default_Communication)
		return default_Communication
	default:
		return default_Communication
	}
}
func (receiver __INet_VI_IP_Table) generate(inbound netip.Prefix, conn_bits _INet_Routing) {
	var (
		ip_bits = get_IPPrefix_Bits(inbound)
	)
	switch flag, mask := inbound.IsValid(), inbound.Bits(); {
	case !flag || mask == -1 || int(conn_bits) > int(ip_bits)-mask || (ip_bits != 32 && ip_bits != 128):
		log.Warnf("IP Table '%v', subnetting '%v': invalid data; ACTION: use default '%v/%v' with subnetting '%v'.", inbound, conn_bits, _VIx_Addr, _VIx_bits, _VIx_IF_bits)
		inbound = parse_interface(
			parse_interface(
				netip.ParseAddr(_VIx_Addr)).(netip.Addr).Prefix(int(_VIx_bits))).(netip.Prefix)
		conn_bits = _VIx_IF_bits
		ip_bits = get_IPPrefix_Bits(inbound)
	}

	var (
		conn_mask     = ip_bits - conn_bits
		bits          = ip_bits - _INet_Routing(inbound.Bits())
		total_VI_Conn = _INet_Routing(1 << conn_bits)
		total_VI      = 1 << bits / total_VI_Conn
		min_VI        = _VI_ID(0)
		// max_VI        = total_VI - 1
		min_VI_Conn = _VI_Conn_ID(0)
		// max_VI_Conn   = total_VI_Conn - 1
		curr       = binary.BigEndian.Uint32(inbound.Addr().AsSlice()) + uint32(total_VI*total_VI_Conn)
		curr_slice = make([]byte, 4, 4)
		curr_IP    netip.Addr
	)

	for a := _VI_ID(total_VI); a > min_VI; a-- {
		receiver[a] = &_INet_VI_IP_Table{}
		receiver[a].Conn = make([]netip.Prefix, total_VI_Conn, total_VI_Conn)
		for c := _VI_Conn_ID(total_VI_Conn); c > min_VI_Conn; c-- {
			curr--
			binary.BigEndian.PutUint32(curr_slice, curr)
			curr_IP = parse_interface(netip.AddrFromSlice(curr_slice)).(netip.Addr)
			receiver[a].Conn[c-1] = netip_Addr_Prefix(&curr_IP)
		}
		receiver[a].IPPrefix = parse_interface(curr_IP.Prefix(int(conn_mask))).(netip.Prefix)
	}
}
func (receiver __INet_UI_IP_Table) generate(inbound netip.Prefix, conn_bits _INet_Routing) {
	var (
		ip_bits = get_IPPrefix_Bits(inbound)
	)
	switch flag, mask := inbound.IsValid(), inbound.Bits(); {
	case !flag || mask == -1 || int(conn_bits) > int(ip_bits)-mask || (ip_bits != 32 && ip_bits != 128):
		log.Warnf("IP Table '%v', subnetting '%v': invalid data; ACTION: use default '%v/%v' with subnetting '%v'.", inbound, conn_bits, _UIx_Addr, _UIx_bits, _UIx_IP_bits)
		inbound = parse_interface(
			parse_interface(
				netip.ParseAddr(_UIx_Addr)).(netip.Addr).Prefix(int(_UIx_bits))).(netip.Prefix)
		conn_bits = _UIx_IP_bits
		ip_bits = get_IPPrefix_Bits(inbound)
	}

	var (
		conn_mask     = ip_bits - conn_bits
		bits          = ip_bits - _INet_Routing(inbound.Bits())
		total_UI_Conn = _INet_Routing(1 << conn_bits)
		total_UI      = 1 << bits / total_UI_Conn
		min_UI        = _INet_Routing(0)
		// max_UI        = total_UI - 1
		min_UI_Conn = _INet_Routing(0)
		// max_UI_Conn   = total_UI_Conn - 1
		curr       = binary.BigEndian.Uint32(inbound.Addr().AsSlice()) + uint32(total_UI*total_UI_Conn)
		curr_slice = make([]byte, 4, 4)
		curr_IP    netip.Addr
	)

	for a := total_UI; a > min_UI; a-- {
		var (
			v_Output = &_INet_UI_IP_Table{}
		)
		v_Output.Conn = make([]netip.Prefix, total_UI_Conn, total_UI_Conn)
		v_Output.Conn_Key = make([]_Secret, total_UI_Conn, total_UI_Conn)
		for c := total_UI_Conn; c > min_UI_Conn; c-- {
			curr--
			binary.BigEndian.PutUint32(curr_slice, curr)
			curr_IP = parse_interface(netip.AddrFromSlice(curr_slice)).(netip.Addr)
			v_Output.Conn[c-1] = netip_Addr_Prefix(&curr_IP)
		}
		switch {
		case a <= 7:
			v_Output.User = &i_LDAP_Domain_User{}
		}
		receiver[parse_interface(curr_IP.Prefix(int(conn_mask))).(netip.Prefix)] = v_Output
	}
}
func (receiver *_Content) parse_GT(inbound any) (outbound _Content) {
	var (
		buffer    = new(bytes.Buffer)
		v_GT, err = template.New("receiver").Parse(receiver.String())
	)
	switch {
	case err != nil || v_GT == nil:
		log.Warnf("template parse error: '%v'; ACTION: return ''.", err)
		return
	}
	switch err = v_GT.Execute(buffer, inbound); {
	case err != nil:
		log.Warnf("template execute error: '%v'; ACTION: report.", err)
		return
	}
	switch { // x == nil and len(x) == 0 not the same, so ....
	case buffer.Len() == 0:
		return _Content{}
	}
	return buffer.Bytes()
}

func (receiver *_strings) filter() (outbound _strings) {
	var (
		interim = make(map[string]bool)
	)
	for _, b := range *receiver {
		switch _, flag := interim[b]; {
		case !flag:
			interim[b] = true
		}
	}
	for a := range interim {
		outbound = append(outbound, a)
	}
	sort.Slice(outbound, func(i, j int) bool {
		return outbound[i] < outbound[j]
	})
	return
}

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func hash(inbound interface{}) (outbound _hash_ID) {
	var (
		interim     = convert_2_string("", inbound)
		value, flag = hash_cache.Load(interim)
	)
	switch {
	case flag && value.([_hash_Size]uint8) != outbound:
		return value.([_hash_Size]uint8)
	case flag:
		log.Warnf("Daemon: hash error - zero result from hash_cache.Load(%+v); ACTION: try to recover.", interim)
	}
	switch value = sha3.Sum512([]uint8(interim)); {
	case value.([_hash_Size]uint8) != outbound:
		hash_cache.Store(interim, value.([_hash_Size]uint8))
		return value.([_hash_Size]uint8)
	default:
		log.Panicf("Daemon: hash error - zero result from hash(%+v); ACTION: panic.", []uint8(interim))
	}
	return
}
func parse_interface(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch {
		case value != nil:
			log.Debugf("'%v'", skip)
		}
	case bool:
		switch {
		case !value:
			log.Debugf("'%v'", skip)
		}
	}
	return inbound
}
func parse_interface_error(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch {
		case value != nil:
			log.Debugf("'%v'", skip)
			return nil
		}
	case bool:
		switch {
		case !value:
			log.Debugf("'%v'", skip)
			return nil
		}
	}
	return inbound
}

func tabber(inbound string, tabs int) string {
	var (
		in_length  = len(inbound)
		tab_length = 8
		max_length = tabs*tab_length - 1
	)
	switch {
	case in_length > max_length:
		return inbound[:max_length]
	case in_length < max_length:
		var (
			add_tabs string
		)
		for counter := max_length - in_length - tab_length; counter >= 0; counter -= tab_length {
			add_tabs += "\t"
		}
		return inbound + add_tabs
	default:
		return inbound
	}
}

func convert_2_string(delimiter string, inbound interface{}) string {
	// return fmt.Sprintf("%s", inbound)
	switch value := (inbound).(type) {
	case *string:
		return *value
	case *_ASN:
		return strconv.FormatUint(uint64(*value), 10)
	case *_W:
		return (*value).String()
	case *_Communication:
		return (*value).String()
	case *_Content:
		return (*value).String()
	case *_Default:
		return (*value).String()
	case *_Description:
		return (*value).String()
	case *_FQDN:
		return (*value).String()
	case *_hash_ID:
		return (*value).String()
	case *_ID:
		return (*value).String()
	case *_IDName:
		return (*value).String()
	case *_Mask:
		return (*value).String()
	case *_Name:
		return (*value).String()
	case *_PName:
		return (*value).String()
	case *_Port:
		return (*value).String()
	case *_Protocol:
		return (*value).String()
	case *_Route_Weight:
		return (*value).String()
	case *_Secret:
		return (*value).String()
	case *_Service:
		return (*value).String()
	case *_Type:
		return (*value).String()
	case *_VI_ID:
		return (*value).String()
	case *_VI_Peer_ID:
		return (*value).String()
	case *[]byte:
		return string(*value)
	case *uint:
		return strconv.FormatUint(uint64(*value), 10)
	case *uint8:
		return strconv.FormatUint(uint64(*value), 10)
	case *uint16:
		return strconv.FormatUint(uint64(*value), 10)
	case *uint32:
		return strconv.FormatUint(uint64(*value), 10)
	case *uint64:
		return strconv.FormatUint(*value, 10)
	case *netip.Addr:
		return (*value).String()
	case *netip.Prefix:
		return (*value).String()
	case string:
		return value
	case _ASN:
		return strconv.FormatUint(uint64(value), 10)
	case _W:
		return value.String()
	case _Communication:
		return value.String()
	case _Content:
		return value.String()
	case _Default:
		return value.String()
	case _Description:
		return value.String()
	case _FQDN:
		return value.String()
	case _hash_ID:
		return value.String()
	case _ID:
		return value.String()
	case _IDName:
		return value.String()
	case _Mask:
		return value.String()
	case _Name:
		return value.String()
	case _PName:
		return value.String()
	case _Port:
		return value.String()
	case _Protocol:
		return value.String()
	case _Route_Weight:
		return value.String()
	case _Secret:
		return value.String()
	case _Service:
		return value.String()
	case _Type:
		return value.String()
	case _VI_ID:
		return value.String()
	case _VI_Peer_ID:
		return value.String()
	case []byte:
		return string(value)
	case uint:
		return strconv.FormatUint(uint64(value), 10)
	case uint8:
		return strconv.FormatUint(uint64(value), 10)
	case uint16:
		return strconv.FormatUint(uint64(value), 10)
	case uint32:
		return strconv.FormatUint(uint64(value), 10)
	case uint64:
		return strconv.FormatUint(value, 10)
	case netip.Addr:
		return value.String()
	case netip.Prefix:
		return value.String()

	case []_Name:
		var (
			inbounds = len(value) - 1
			buffer   bytes.Buffer
		)
		for a, b := range value {
			switch {
			case len(b) == 0:
				continue
			}
			buffer.WriteString(b.String())
			switch {
			case a < inbounds:
				buffer.WriteString(delimiter)
			}
		}
		return buffer.String()

	default:
		log.Debugf("unsupported type '%v' of '%s'; ACTION: use fmt.Sprintf().", reflect.TypeOf(inbound), inbound)
		return fmt.Sprintf("%s", value)
		// log.Fatalf("unsupported type '%v'; ACTION: fatal.", reflect.TypeOf(inbound))
		// return ""
	}
}
func pad(inbound interface{}, length int) _PName {
	return _PName(pad_string(convert_2_string("", inbound), length))
}
func pad_string(inbound string, length int) string {
	var (
		padding string
	)
	switch c := length - len(inbound); {
	case c > 0:
		for a := 0; a < c; a++ {
			padding += "0"
		}
	}
	return padding + inbound
}

func trim_space(inbound interface{}) _Content {
	var (
		interim string
	)
	for _, value := range strings.Split(convert_2_string("", inbound), "\n") {
		interim += strings.TrimSpace(value) + "\n"
	}
	return _Content(interim)
}
func split_2_string(inbound interface{}, re *regexp.Regexp, target ...*string) {
	var (
		interim = re.Split(convert_2_string("", inbound), -1)
	)
	for a := 0; a < len(interim) && a < len(target); a++ {
		*target[a] = interim[a]
	}
}

func get_VI_IPPrefix(vi_id _VI_ID, peer_id _VI_Peer_ID) netip.Prefix {
	var (
		b = make([]byte, 4)
	)
	binary.BigEndian.PutUint32(b, _Settings[_VI_IPShift].(uint32)+uint32(vi_id*4)+uint32(peer_id))
	return netip.PrefixFrom(parse_interface(netip.AddrFromSlice(b)).(netip.Addr), 30)
}
func set_VI_IPPrefix(inbound ...netip.Prefix) (ok bool) {
	switch {
	case len(inbound) == 1 && inbound[0].IsValid():
		_Settings[_VI_IPPrefix] = inbound[0]
		ok = true
	}
	_Settings[_VI_IPShift] = binary.BigEndian.Uint32(_Settings[_VI_IPPrefix].(netip.Prefix).Addr().AsSlice())
	return
}
func set_Domain_Name(inbound ..._FQDN) (ok bool) {
	switch {
	case len(inbound) == 1 && len(inbound[0]) != 0:
		_Settings[_domain_name] = inbound[0]
		ok = true
	}
	return
}

// func sum_string_gt_fm(inbound ...interface{}) (outbound string) {
// 	switch len(inbound) {
// 	case 0:
// 		return
// 	}
// 	for _, value := range inbound {
// 		outbound += convert_2_string("", value)
// 	}
// 	return
// }

func parse_Communication(_peer *_ASN, _if *_Name, inbound *_Communication) _Communication {
	switch {
	case *inbound == _Communication_ptp || *inbound == _Communication_ptmp:
		return *inbound
	case len(*inbound) != 0:
		log.Warnf("Peer '%v', IF '%v', invalid Communication type '%v'; ACTION: use '%v'.", _peer, _if, *inbound, _Settings[_comm_if].(_Communication))
		fallthrough
	default:
		return _Settings[_comm_if].(_Communication)
	}
}
func parse_Host_Inbound_Traffic(enabled ...interface{}) (outbound _Host_Inbound_Traffic_List) {
	outbound = _Host_Inbound_Traffic_List{
		Services:  map[_Service]bool{},
		Protocols: map[_Protocol]bool{},
		GT_Action: _W_host__inbound__traffic.String() + " ",
	}
	for _, b := range enabled {
		switch value := b.(type) {
		case _Service:
			outbound.Services[value] = true
		case _Protocol:
			outbound.Protocols[value] = true
		}
	}
	return
}

func read_GT() (ok bool) {
	var (
		dentry []os.DirEntry
		data   []byte
		err    error
	)
	switch dentry, err = os.ReadDir(_Settings[_dirname_GT].(string)); {
	case err != nil:
		log.Warnf("template director '%v' read error '%v'; ACTION: skip.", _Settings[_dirname_GT], err)
		return
	}
	for _, fentry := range dentry {
		switch {
		case !fentry.Type().IsRegular():
			continue
		}
		var (
			fsplit = re_dot.Split(fentry.Name(), -1)
		)
		switch {
		case len(fsplit) < 1:
			continue
		}
		switch {
		case fsplit[len(fsplit)-1] != "tmpl":
			continue
		}
		var (
			tname = _Name(fentry.Name()[:len(fentry.Name())-5])
		)
		switch data, err = os.ReadFile(strings_join("/", _Settings[_dirname_GT], fentry.Name())); {
		case err != nil:
			log.Warnf("template '%v' read error '%v'; ACTION: skip.", tname, err)
			continue
		}
		switch _, flag := i_gt[tname]; {
		case flag:
			log.Warnf("template '%v' already exist; ACTION: skip.", tname)
			continue
		}
		i_gt[tname] = &i_GT{
			Content: trim_space(&data),
		}
	}
	return err == nil
}

func action_Port(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, port, port_low, port_high _Port) (outbound string /* , ok bool */) {
	switch {
	// case port != 0:
	// 	outbound = port.String()
	case port_low != 0:
		outbound = port_low.String()
		fallthrough
	case port_low != 0 && port_high != 0:
		outbound = strings_join(" ", outbound, _W_to, port_high)
	default:
		return
	}
	switch {
	case inbound_type == _Type_static && inbound_direction == _Type_from:
		outbound = strings_join(" ", _W_source__port, outbound)
	case inbound_type == _Type_static && inbound_direction == _Type_to:
		outbound = strings_join(" ", _W_destination__port, outbound)
	case inbound_type == _Type_static && inbound_direction == _Type_then:
		outbound = strings_join(" ", _W_mapped__port, outbound)
	}

	return
}

func strings_join(delimiter string, inbound ...interface{}) (outbound string) {
	var (
		interim []string
	)
	for _, b := range inbound {
		interim = append(interim, convert_2_string(delimiter, b))
	}
	var (
		inbounds = len(interim) - 1
		buffer   bytes.Buffer
	)
	for a, b := range interim {
		switch {
		case len(b) == 0:
			continue
		}
		buffer.WriteString(b)
		switch {
		case a < inbounds:
			buffer.WriteString(delimiter)
		}
	}
	return buffer.String()
}

func parse_cDB_Route_Leak(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak *cDB_Peer_RI_RO_Route_Leak) (outbound map[_W]i_Route_Leak_FromTo /* , ok bool */) {
	// outbound = make(map[_W]i_Route_Leak_FromTo)
	return parse_iDB_Route_Leak(nil, v_Peer, "", "", &map[_W]i_Route_Leak_FromTo{
		_W_import: {PS: func() (outbound []_Name) {
			for _, b := range (*route_leak).Import {
				outbound = append(outbound, b.PS)
			}
			return
		}()},
		_W_export: {PS: func() (outbound []_Name) {
			for _, b := range (*route_leak).Export {
				outbound = append(outbound, b.PS)
			}
			return
		}()},
	})
}
func parse_iDB_Route_Leak(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak *map[_W]i_Route_Leak_FromTo) (outbound map[_W]i_Route_Leak_FromTo /* , ok bool */) {
	outbound = make(map[_W]i_Route_Leak_FromTo)
	var (
		v_RL_Import = func() (outbound []_Name) {
			for _, b := range (*route_leak)[_W_import].PS {
				switch _, flag := i_ps[b]; {
				case !flag:
					log.Warnf("Peer '%v', PL '%v' not found; ACTION: ignore.", v_Peer.ASN, b)
					continue
				}
				outbound = append(outbound, b)
				v_Peer.link_PS(b)
			}
			return
		}()
		v_RL_Export = func() (outbound []_Name) {
			for _, b := range (*route_leak)[_W_export].PS {
				switch _, flag := i_ps[b]; {
				case !flag:
					log.Warnf("Peer '%v', PL '%v' not found; ACTION: ignore.", v_Peer.ASN, b)
					continue
				}
				outbound = append(outbound, b)
				v_Peer.link_PS(b)
			}
			return
		}()
	)
	switch {
	case len(v_RL_Import) != 0:
		outbound[_W_import] = i_Route_Leak_FromTo{
			PS:              v_RL_Import,
			GT_Action:       strings_join(" ", _W_import, "[", v_RL_Import, "]"),
			_Attribute_List: (*route_leak)[_W_import]._Attribute_List,
		}
	}
	switch {
	case len(v_RL_Export) != 0:
		outbound[_W_export] = i_Route_Leak_FromTo{
			PS:              v_RL_Export,
			GT_Action:       strings_join(" ", _W_export, "[", v_RL_Export, "]"),
			_Attribute_List: (*route_leak)[_W_export]._Attribute_List,
		}
	}
	return
}

func convert_netip_Addr_Prefix(inbound *netip.Addr) (outbound netip.Prefix) {
	return parse_interface((*inbound).Prefix((*inbound).BitLen())).(netip.Prefix)
}

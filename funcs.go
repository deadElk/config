package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func hash(inbound interface{}) (outbound _ID) {
	var (
		interim     = convert_2_string(inbound)
		value, flag = hash_cache.Load(interim)
	)
	switch {
	case flag && value.([_hash_Size]uint8) != outbound:
		return value.([_hash_Size]uint8)
	case flag:
		log.Warnf("Daemon: hash error - zero result from hash_cache.Load(%+v); ACTION: try to recover.", interim)
	}
	switch value = sha3.Sum512([]uint8(interim)); value.([_hash_Size]uint8) != outbound {
	case true:
		hash_cache.Store(interim, value.([_hash_Size]uint8))
		return value.([_hash_Size]uint8)
	default:
		log.Panicf("Daemon: hash error - zero result from hash(%+v); ACTION: panic.", []uint8(interim))
	}
	return
}
func set_loglevel(inbound ...string) (ok bool) {
	switch len(inbound) == 0 {
	case false:
		switch loglevel, err := log.ParseLevel(inbound[0]); err == nil {
		case true:
			ok = true
			log.SetLevel(loglevel)
		default:
			log.SetLevel(_Defaults[_loglevel].(log.Level))
			// log.Warnf("verbosity level '%v' is not supported; ACTION: use '%v'.", *inbound[0], log.GetLevel())
		}
	default:
		log.SetLevel(_Defaults[_loglevel].(log.Level))
	}
	return
}
func parse_interface(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch value == nil {
		case false:
			log.Debugf("'%v'", skip)
		}
	case bool:
		switch value {
		case false:
			log.Debugf("'%v'", skip)
		}
	}
	return inbound
}
func parse_interface_error(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch value == nil {
		case false:
			log.Debugf("'%v'", skip)
			return nil
		}
	case bool:
		switch value {
		case false:
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

func convert_2_string(inbound interface{}) string {
	// switch value := inbound.(type) {
	// case interface{}:
	// 	return fmt.Sprintf("%s", value)
	// case *interface{}:
	// 	return fmt.Sprintf("%s", value)
	// }
	// return ""
	// switch reflect.ValueOf(inbound).Kind() {
	// case reflect.Ptr:
	// 	return fmt.Sprintf("%s", reflect.ValueOf(inbound))
	// }
	// return fmt.Sprintf("%s", reflect.ValueOf(inbound))

	return fmt.Sprintf("%s", inbound)

	// switch value := (inbound).(type) {
	// case *string:
	// 	return *value
	// case *_Name:
	// 	return (*value).String()
	// case *_PName:
	// 	return (*value).String()
	// case *_VI_ID:
	// 	return (*value).String()
	// case *_VI_Peer_ID:
	// 	return (*value).String()
	// case *_ASN:
	// 	return (*value).String()
	// case *_Content:
	// 	return (*value).String()
	// case *[]byte:
	// 	return string(*value)
	// case *uint:
	// 	return strconv.FormatUint(uint64(*value), 10)
	// case *uint8:
	// 	return strconv.FormatUint(uint64(*value), 10)
	// case *uint16:
	// 	return strconv.FormatUint(uint64(*value), 10)
	// case *uint32:
	// 	return strconv.FormatUint(uint64(*value), 10)
	// case *uint64:
	// 	return strconv.FormatUint(*value, 10)
	// // case string:
	// // 	return value
	// // case _Name:
	// // 	return value.String()
	// // case _PName:
	// // 	return value.String()
	// // case _VI_ID:
	// // 	return value.String()
	// // case _VI_Peer_ID:
	// // 	return value.String()
	// // case _ASN:
	// // 	return value.String()
	// // case _Content:
	// // 	return value.String()
	// // case []byte:
	// // 	return string(value)
	// // case uint:
	// // 	return strconv.FormatUint(uint64(value), 10)
	// // case uint8:
	// // 	return strconv.FormatUint(uint64(value), 10)
	// // case uint16:
	// // 	return strconv.FormatUint(uint64(value), 10)
	// // case uint32:
	// // 	return strconv.FormatUint(uint64(value), 10)
	// // case uint64:
	// // 	return strconv.FormatUint(value, 10)
	// default:
	// 	log.Fatalf("unsupported type '%v'; ACTION: fatal.", reflect.TypeOf(inbound))
	// 	return ""
	// }
}
func pad(inbound interface{}, length int) _PName {
	var (
		padding string
		interim = convert_2_string(inbound)
	)
	switch c := length - len(interim); c > 0 {
	case true:
		for a := 0; a < c; a++ {
			padding += "0"
		}
	}
	return _PName(padding + interim)
}
func trim_space(inbound interface{}) _Content {
	var (
		interim string
	)
	for _, value := range strings.Split(convert_2_string(inbound), "\n") {
		interim += strings.TrimSpace(value) + "\n"
	}
	return _Content(interim)
}
func split_2_string(inbound interface{}, re *regexp.Regexp, target ...*string) {
	var (
		interim = re.Split(convert_2_string(inbound), -1)
	)
	for a := 0; a < len(interim) && a < len(target); a++ {
		*target[a] = interim[a]
	}
}

func get_VI_IPPrefix(vi_id _VI_ID, peer_id _VI_Peer_ID) netip.Prefix {
	var (
		b = make([]byte, 4)
	)
	binary.BigEndian.PutUint32(b, _Defaults[_VI_IPShift].(uint32)+uint32(vi_id*4)+uint32(peer_id))
	return netip.PrefixFrom(parse_interface(netip.AddrFromSlice(b)).(netip.Addr), 30)
}
func set_VI_IPPrefix(inbound ...netip.Prefix) (ok bool) {
	switch len(inbound) == 1 && inbound[0].IsValid() {
	case true:
		_Defaults[_VI_IPPrefix] = inbound[0]
		ok = true
	}
	_Defaults[_VI_IPShift] = binary.BigEndian.Uint32(_Defaults[_VI_IPPrefix].(netip.Prefix).Addr().AsSlice())
	return
}
func set_Domain_Name(inbound ..._FQDN) (ok bool) {
	switch len(inbound) == 1 && len(inbound[0]) != 0 {
	case true:
		_Defaults[_domain_name] = inbound[0]
		ok = true
	}
	return
}
func sum_string_gt_fm(inbound ...interface{}) (outbound string) {
	switch len(inbound) {
	case 0:
		return
	}
	for _, value := range inbound {
		outbound += convert_2_string(value)
	}
	return
}

func parse_Communication(_peer *_ASN, _if *_Name, inbound *_Communication) _Communication {
	switch {
	case *inbound == _Communication_ptp || *inbound == _Communication_ptmp:
		return *inbound
	case len(*inbound) != 0:
		log.Warnf("Peer '%v', IF '%v', invalid Communication type '%v'; ACTION: use '%v'.", _peer, _if, *inbound, _Defaults[_comm_if].(_Communication))
		fallthrough
	default:
		return _Defaults[_comm_if].(_Communication)
	}
}
func parse_Host_Inbound_Traffic(enabled ...interface{}) (outbound _Host_Inbound_Traffic_List) {
	outbound = _Host_Inbound_Traffic_List{
		Services:  map[_Service]bool{},
		Protocols: map[_Protocol]bool{},
		GT_Action: "host-inbound-traffic ",
	}
	// _GT_Action_List: _GT_Action_List{GT_Action: "host-inbound-traffic "},
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
	switch dentry, err = os.ReadDir(_Defaults[_path_GT].(string)); err == nil {
	case false:
		log.Warnf("template director '%v' read error '%v'; ACTION: skip.", _Defaults[_path_GT], err)
		return
	}
	for _, fentry := range dentry {
		switch fentry.Type().IsRegular() {
		case false:
			continue
		}
		var (
			fsplit = re_dot.Split(fentry.Name(), -1)
		)
		switch len(fsplit) < 1 {
		case true:
			continue
		}
		switch fsplit[len(fsplit)-1] == "tmpl" {
		case false:
			continue
		}
		var (
			tname = _Name(fentry.Name()[:len(fentry.Name())-5])
		)
		switch data, err = os.ReadFile(_Defaults[_path_GT].(string) + "/" + fentry.Name()); err == nil {
		case false:
			log.Warnf("template '%v' read error '%v'; ACTION: skip.", tname, err)
			continue
		}
		switch _, flag := i_gt[tname]; flag {
		case true:
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
	// 	outbound = " " + port_low.String() + " "
	case port_low != 0:
		outbound = " " + port_low.String() + " "
		fallthrough
	case port_low != 0 && port_high != 0:
		outbound += " to " + port_high.String() + " "
	default:
		return
	}
	switch {
	case inbound_type == _Type_static && inbound_direction == _Type_from:
		outbound = " source-port " + outbound + " "
	case inbound_type == _Type_static && inbound_direction == _Type_to:
		outbound = " destination-port " + outbound + " "
	case inbound_type == _Type_static && inbound_direction == _Type_then:
		outbound = " mapped-port " + outbound + " "
	}

	return
}

func strings_Join(inbound []_Name, delimiter string) (outbound _Name) {
	var (
		inbounds = len(inbound) - 1
		buffer   bytes.Buffer
	)
	for a, b := range inbound {
		buffer.WriteString(string(b))
		switch a < inbounds {
		case true:
			buffer.WriteString(delimiter)
		}
	}
	return _Name(buffer.String())
}

func parse_cDB_Route_Leak(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak *cDB_Peer_RI_RO_Route_Leak) (outbound map[_Action]i_Route_Leak_FromTo /* , ok bool */) {
	outbound = make(map[_Action]i_Route_Leak_FromTo)
	return parse_iDB_Route_Leak(nil, v_Peer, "", "", &map[_Action]i_Route_Leak_FromTo{
		_Action_import: {PS: func() (outbound []_Name) {
			for _, b := range (*route_leak).Import {
				outbound = append(outbound, b.PS)
			}
			return
		}()},
		_Action_export: {PS: func() (outbound []_Name) {
			for _, b := range (*route_leak).Export {
				outbound = append(outbound, b.PS)
			}
			return
		}()},
	})
}
func parse_iDB_Route_Leak(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, route_leak *map[_Action]i_Route_Leak_FromTo) (outbound map[_Action]i_Route_Leak_FromTo /* , ok bool */) {
	outbound = make(map[_Action]i_Route_Leak_FromTo)
	var (
		v_RL_Import = func() (outbound []_Name) {
			for _, b := range (*route_leak)[_Action_import].PS {
				switch _, flag := i_ps[b]; flag {
				case false:
					log.Warnf("Peer '%v', PL '%v' not found; ACTION: ignore.", v_Peer.ASN, b)
					continue
				}
				outbound = append(outbound, b)
				v_Peer.link_PS(b)
			}
			return
		}()
		v_RL_Export = func() (outbound []_Name) {
			for _, b := range (*route_leak)[_Action_export].PS {
				switch _, flag := i_ps[b]; flag {
				case false:
					log.Warnf("Peer '%v', PL '%v' not found; ACTION: ignore.", v_Peer.ASN, b)
					continue
				}
				outbound = append(outbound, b)
				v_Peer.link_PS(b)
			}
			return
		}()
	)
	return map[_Action]i_Route_Leak_FromTo{
		_Action_import: {
			PS:              v_RL_Import,
			GT_Action:       " " + _Action_import.String() + " [ " + strings_Join(v_RL_Import, " ").String() + " ] ",
			_Attribute_List: (*route_leak)[_Action_import]._Attribute_List,
		},
		_Action_export: {
			PS:              v_RL_Export,
			GT_Action:       " " + _Action_export.String() + " [ " + strings_Join(v_RL_Export, " ").String() + " ] ",
			_Attribute_List: (*route_leak)[_Action_export]._Attribute_List,
		},
	}
}

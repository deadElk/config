package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func hash(inbound *string) (outbound _ID) {
	var (
		value, flag = hash_cache.Load(*inbound)
	)
	switch {
	case flag && value.([_hash_Size]uint8) != outbound:
		return value.([_hash_Size]uint8)
	case flag:
		log.Warnf("Daemon: hash error - zero result from hash_cache.Load(%+v); ACTION: try to recover.", inbound)
	}
	switch value = sha3.Sum512([]uint8(*inbound)); value.([_hash_Size]uint8) != outbound {
	case true:
		hash_cache.Store(*inbound, value.([_hash_Size]uint8))
		return value.([_hash_Size]uint8)
	default:
		log.Panicf("Daemon: hash error - zero result from hash(%+v); ACTION: panic.", []uint8(*inbound))
	}
	return
}
func set_loglevel(inbound ...string) {
	switch len(inbound) == 0 {
	case false:
		switch loglevel, err := log.ParseLevel(inbound[0]); err == nil {
		case true:
			log.SetLevel(loglevel)
		default:
			log.SetLevel(_Defaults[_loglevel].(log.Level))
			// log.Warnf("verbosity level '%v' is not supported; ACTION: use '%v'.", *inbound[0], log.GetLevel())
		}
	default:
		log.SetLevel(_Defaults[_loglevel].(log.Level))
	}
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
	switch value := (inbound).(type) {
	case *string:
		return *value
	case *_Name:
		return (*value).String()
	case *_PName:
		return (*value).String()
	case *_VI_ID:
		return (*value).String()
	case *_VI_Peer_ID:
		return (*value).String()
	case *_ASN:
		return (*value).String()
	case *_Content:
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
	// case string:
	// 	return value
	// case _Name:
	// 	return value.String()
	// case _PName:
	// 	return value.String()
	// case _VI_ID:
	// 	return value.String()
	// case _VI_Peer_ID:
	// 	return value.String()
	// case _ASN:
	// 	return value.String()
	// case _Content:
	// 	return value.String()
	// case []byte:
	// 	return string(value)
	// case uint:
	// 	return strconv.FormatUint(uint64(value), 10)
	// case uint8:
	// 	return strconv.FormatUint(uint64(value), 10)
	// case uint16:
	// 	return strconv.FormatUint(uint64(value), 10)
	// case uint32:
	// 	return strconv.FormatUint(uint64(value), 10)
	// case uint64:
	// 	return strconv.FormatUint(value, 10)
	default:
		log.Fatalf("unsupported type '%v'; ACTION: fatal.", reflect.TypeOf(inbound))
		return ""
	}
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
func set_VI_IPPrefix(inbound ...netip.Prefix) {
	switch len(inbound) == 1 && inbound[0].IsValid() {
	case true:
		_Defaults[_VI_IPPrefix] = inbound[0]
	}
	_Defaults[_VI_IPShift] = binary.BigEndian.Uint32(_Defaults[_VI_IPPrefix].(netip.Prefix).Addr().AsSlice())
}
func set_Domain_Name(inbound ..._FQDN) {
	switch len(inbound) == 1 && len(inbound[0]) != 0 {
	case true:
		_Defaults[_domain_name] = inbound[0]
	}
}
func sum_string_gt_fm(inbound ...interface{}) (outbound string) {
	switch len(inbound) {
	case 0:
		return
	}
	for _, value := range inbound {
		switch element := value.(type) {
		case string:
			outbound += element
		case _Name:
			outbound += element.String()
		case _PName:
			outbound += element.String()
		case uint:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint8:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint16:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint32:
			outbound += strconv.FormatUint(uint64(element), 10)
		case uint64:
			outbound += strconv.FormatUint(element, 10)
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
		i_gt[tname] = i_GT{
			Content: trim_space(&data),
		}
	}
	return err == nil
}
func create_AB(ab_name _Name, sa *_Service_Attributes) (ok bool) {
	switch _, flag := i_ab[ab_name]; flag {
	case true:
		log.Warnf("Address Book '%+v', already exist; ACTION: skip.", ab_name)
		return
	}
	i_ab[ab_name] = i_AB{
		Type:                _Type_set,
		Address:             nil,
		Addresses:           map[_Name]_Type{},
		_Service_Attributes: *sa,
	}
	return true
}
func add_2_AB(public, private bool, ab_name _Name, inbound ...interface{}) (ok bool) {
	var (
		interim []interface{}
	)
	for _, address := range inbound {
		switch value := (address).(type) {
		case netip.Addr:
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
			case true:
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
			var (
				bits = 32
			)
			switch value.Is6() {
			case true:
				bits = 128
			}
			interim = append(interim, parse_interface(value.Prefix(bits)).(netip.Prefix))
		case netip.Prefix:
			switch is_private, is_valid := value.Masked().Addr().IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
			case true:
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
			interim = append(interim, value)
		case _FQDN:
			switch len(value) == 0 {
			case true:
				continue
			}
			interim = append(interim, value)
		case _Name:
			switch len(value) == 0 {
			case true:
				continue
			}
			interim = append(interim, value)
		default:
			log.Warnf("AB '%v', address '%v'; unknown address type; ACTION: skip.", ab_name, value)
			continue
		}
	}

	for _, address := range interim {
		switch _, flag := i_ab[ab_name]; {
		case flag && i_ab[ab_name].Type == _Type_set:
			switch value := (address).(type) {
			case _Name:
				ok = true
				i_ab[ab_name].Addresses[value] = _Type_set
			case _FQDN:
				ok = true
				i_ab[ab_name].Addresses[value._Name()] = _Type_fqdn
				add_2_AB(true, true, value._Name(), value)
			case netip.Prefix:
				var (
					ab = _Name(value.String())
				)
				ok = true
				i_ab[ab_name].Addresses[ab] = _Type_ipprefix
				add_2_AB(true, true, ab, value)
			}
		case flag:
			log.Warnf("AB '%+v''%+v', already exist; ACTION: skip.", ab_name, i_ab[ab_name])
			continue
		default:
			switch value := (address).(type) {
			case _FQDN:
				ok = true
				i_ab[ab_name] = i_AB{
					Type:    _Type_fqdn,
					Address: value,
				}
			case netip.Prefix:
				ok = true
				i_ab[ab_name] = i_AB{
					Type:    _Type_ipprefix,
					Address: value,
				}
			}
		}
	}
	return
}

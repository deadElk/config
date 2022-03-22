package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"

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
			log.Debugf("'%v', '%v'", inbound, skip)
		}
	case bool:
		switch {
		case !value:
			log.Debugf("'%v', '%v'", inbound, skip)
		}
	default:
		log.Debugf("'%v', '%v'", inbound, skip)
	}
	return inbound
}
func parse_interface_error(inbound interface{}, skip interface{}) interface{} {
	switch value := skip.(type) {
	case error:
		switch {
		case value != nil:
			log.Debugf("'%v', '%v'", inbound, skip)
			return nil
		}
	case bool:
		switch {
		case !value:
			log.Debugf("'%v', '%v'", inbound, skip)
			return nil
		}
	default:
		log.Debugf("'%v', '%v'", inbound, skip)
	}
	return inbound
}

func string_uint64(inbound string) uint64 {
	return parse_interface(strconv.ParseUint(inbound, 10, 64)).(uint64)
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

func convert_2_string(delimiter string, inbound any) (outbound string) {
	switch value := (inbound).(type) {
	case *string:
		return *value
	case *_Inet_ASN:
		return (*value).String()
	case *_W:
		return (*value).String()
	case *_Communication:
		return (*value).String()
	case *_Content:
		return (*value).String()
	case *_S:
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
	case *_INet_Port:
		return (*value).String()
	case *_INet_Protocol:
		return (*value).String()
	case *_INet_Routing:
		return (*value).String()
	case *_Secret:
		return (*value).String()
	case *_Service:
		return (*value).String()
	case *_Type:
		return (*value).String()
	case *_VI_ID:
		return (*value).String()
	case *_VI_Conn_ID:
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
	case *io.Reader:
		switch interim, err := ioutil.ReadAll(*value); {
		case err == nil:
			return string(interim)
		}
		return
	case string:
		return value
	case _Inet_ASN:
		return value.String()
	case _W:
		return value.String()
	case _Communication:
		return value.String()
	case _Content:
		return value.String()
	case _S:
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
	case _INet_Port:
		return value.String()
	case _INet_Protocol:
		return value.String()
	case _INet_Routing:
		return value.String()
	case _Secret:
		return value.String()
	case _Service:
		return value.String()
	case _Type:
		return value.String()
	case _VI_ID:
		return value.String()
	case _VI_Conn_ID:
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
	case io.Reader:
		switch interim, err := ioutil.ReadAll(value); {
		case err == nil:
			return string(interim)
		}
		return

		// todo: dirty hack
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
func split_2_string(inbound any, re *regexp.Regexp, target ...*string) {
	var (
		interim = re.Split(convert_2_string("", inbound), -1)
	)
	for a := 0; a < len(interim) && a < len(target); a++ {
		*target[a] = interim[a]
	}
}

func parse_Host_Inbound_Traffic(enabled ...any) (outbound _Host_Inbound_Traffic_List) {
	outbound = _Host_Inbound_Traffic_List{
		Services:  map[_Service]bool{},
		Protocols: map[_INet_Protocol]bool{},
		GT_Action: _W_host__inbound__traffic.String() + " ",
	}
	for _, b := range enabled {
		switch value := b.(type) {
		case _Service:
			outbound.Services[value] = true
		case _INet_Protocol:
			outbound.Protocols[value] = true
		}
	}
	return
}

func read_file() (not_ok bool) {
	for a, b := range i_read_list {
		switch direntry, err := os.ReadDir(a.String()); {
		case err == nil:
			for _, f := range direntry {
				switch {
				case !f.Type().IsRegular():
					continue
				}
				var (
					s = re_dots.Split(f.Name(), -1)
				)
				switch {
				case len(s) < 2 || s[len(s)-1] != string(b.ext):
					log.Warnf("inconsistent filename '%v'; ACTION: report.", a)
					not_ok = true
					continue
				}
				var (
					t = _File_Name(f.Name()[:len(f.Name())-1-len(s[len(s)-1])])
					g _Content
				)
				switch g, err = os.ReadFile(strings_join("/", ".", a.String(), f.Name())); {
				case err != nil:
					log.Warnf("file '%v' read error '%v'; ACTION: report.", t, err)
					not_ok = true
					continue
				}
				g.trim_space()
				b.data[t] = &g
				b.sorted = append(b.sorted, t)
			}
			sort.Slice(b.sorted, func(i, j int) bool {
				return b.sorted[i] < b.sorted[j]
			})
		default:
			log.Warnf("directory '%v' read error '%v'; ACTION: report.", a, err)
			// not_ok = true
			continue
		}
	}
	return !not_ok
}
func write_file() (not_ok bool) {
	for a, b := range i_write_list {
		switch err := os.MkdirAll(string(a), os.ModeDir|0700); {
		case err != nil:
			log.Errorf("directory '%v' create error '%v'; ACTION: report.", a, err)
			not_ok = true
			continue
		}
		for e, f := range b.data {
			var (
				g = strings_join("/", a, strings_join(".", e, b.ext))
			)
			switch err := os.WriteFile(g, *f, 0600); {
			case err != nil:
				log.Errorf("file '%v' write error '%v'; ACTION: report.", g, err)
				not_ok = true
				continue
			}
		}
	}
	return !not_ok
}

func action_Port(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, port, port_low, port_high _INet_Port) (outbound string) {
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

func convert_netip_Addr_Prefix(inbound *netip.Addr) (outbound netip.Prefix) {
	return parse_interface((*inbound).Prefix((*inbound).BitLen())).(netip.Prefix)
}
func get_IP_Bits(inbound netip.Addr) (outbound _INet_Routing) {
	switch flag, flag4, flag6 := inbound.IsValid(), inbound.Is4(), inbound.Is6(); { // todo IP.Unmap()?
	case flag && flag4:
		return 32
	case flag && flag6:
		return 128
	}
	return
}
func get_IPPrefix_Bits(inbound netip.Prefix) (outbound _INet_Routing) {
	return get_IP_Bits(inbound.Addr())
}

func inc_big_Int(inbound *big.Int) {
	inbound = inbound.Add(inbound, big.NewInt(1))
}

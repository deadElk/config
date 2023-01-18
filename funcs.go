package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/netip"
	"regexp"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func hash(inbound any) (outbound _hash_ID) {
	var (
		value, flag = hash_cache.Load(inbound)
	)
	switch {
	case flag:
		return value.([_hash_Size]uint8)
	}
	outbound = sha3.Sum512([]uint8(interface_string("", inbound)))
	hash_cache.Store(inbound, outbound)
	return
}
func hash224(inbound any) (outbound _hash224_ID) {
	var (
		value, flag = hash224_cache.Load(inbound)
	)
	switch {
	case flag:
		return value.([_hash224_Size]uint8)
	}
	outbound = sha3.Sum224([]uint8(interface_string("", inbound)))
	hash224_cache.Store(inbound, outbound)
	return
}

// don't forget to check _not_ok before write out anything
func _check() {
	switch {
	case _not_ok:
		log.Fatalf("service-wide OK status NEGATIVE ('%v'), cannot proceed; ACTION: FATAL.", _not_ok)
	}
	// log.Fatalf("service-wide OK status NEGATIVE ('%v'), cannot proceed; ACTION: FATAL.", _not_ok)
}

// don't forget to check _not_ok before write out anything
func _fatal() {
	_not_ok = true
}

func parse_interface(inbound any, skip any) any {
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
func parse_interface_error(inbound any, skip any) any {
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

func tabber(inbound string, tabs int) string { // no words....
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

func interface_string(delimiter string, inbound any) (outbound string) {
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
	case *_Dir_Name:
		return (*value).String()
	case *_File_Name:
		return (*value).String()
	case *_FQDN:
		return (*value).String()
	case *_hash_ID:
		return (*value).String()
	case *_hash224_ID:
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
	case *bytes.Buffer:
		return value.String()
	case *netip.Addr:
		return value.String()
	case *netip.Prefix:
		return value.String()
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
	case _Dir_Name:
		return value.String()
	case _File_Name:
		return value.String()
	case _FQDN:
		return value.String()
	case _hash_ID:
		return value.String()
	case _hash224_ID:
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
	case bytes.Buffer:
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
			interim = func() (outbound []string) {
				for _, b := range value {
					switch {
					case len(b) == 0:
						continue
					}
					outbound = append(outbound, string(b))
				}
				return
			}()
			inbounds = len(interim) - 1
			buffer   = new(bytes.Buffer)
		)
		for a, b := range interim {
			buffer.WriteString(b)
			switch {
			case a < inbounds:
				buffer.WriteString(delimiter)
			}
		}
		return buffer.String()
	case []string:
		var (
			interim = func() (outbound []string) {
				for _, b := range value {
					switch {
					case len(b) == 0:
						continue
					}
					outbound = append(outbound, b)
				}
				return
			}()
			inbounds = len(interim) - 1
			buffer   = new(bytes.Buffer)
		)
		for a, b := range interim {
			buffer.WriteString(b)
			switch {
			case a < inbounds:
				buffer.WriteString(delimiter)
			}
		}
		return buffer.String()

	default:
		// log.Debugf("unsupported type '%v' of '%s'; ACTION: use fmt.Sprintf().", reflect.TypeOf(inbound), inbound)
		return fmt.Sprintf("%s", value)
	}
}
func pad(inbound any, length int) _PName {
	return _PName(pad_string(inbound, length))
}
func pad_string(inbound any, length int) string {
	var (
		padding string
		interim = interface_string("", inbound)
	)
	switch c := length - len(interim); {
	case c > 0:
		for a := 0; a < c; a++ {
			padding += "0"
		}
	}
	return padding + interim
}
func get_string(inbound any, re *regexp.Regexp, target ...*string) {
	var (
		interim = re.Split(interface_string("", inbound), -1)
	)
	for a := 0; a < len(interim) && a < len(target); a++ {
		*target[a] = interim[a]
	}
}
func split_2_strings(inbound any, re *regexp.Regexp) (outbound _strings) {
	var (
		interim = _strings(re.Split(interface_string("", inbound), -1))
	)
	return interim.filter()
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

func action_Port(peer *cDB_Peer, v_Peer *i_Peer, inbound_type _Type, inbound_direction _Type, port, port_low, port_high _INet_Port) (outbound string) {
	switch {
	case port_low != 0:
		outbound = port_low.String()
	default:
		return
	}
	switch {
	case port_high != 0:
		outbound = join_string(" ", outbound, _W_to, port_high)
	default:
		return
	}

	switch {
	case inbound_type == _Type_static && inbound_direction == _Type_from:
		outbound = join_string(" ", _W_source__port, outbound)
	case inbound_type == _Type_static && inbound_direction == _Type_to:
		outbound = join_string(" ", _W_destination__port, outbound)
	case inbound_type == _Type_static && inbound_direction == _Type_then:
		outbound = join_string(" ", _W_mapped__port, outbound)
	}

	return
}

func join_string(delimiter string, inbound ...any) (outbound string) {
	var (
		interim = func() (outbound []string) {
			for _, b := range inbound {
				var (
					c = interface_string(delimiter, b)
				)
				switch {
				case len(c) == 0:
					continue
				}
				outbound = append(outbound, c)
			}
			return
		}()
		inbounds = len(interim) - 1
		buffer   = new(bytes.Buffer)
	)
	for a, b := range interim {
		buffer.WriteString(b)
		switch {
		case a < inbounds:
			buffer.WriteString(delimiter)
		}
	}
	return buffer.String()
}

func inc_big_Int(inbound *big.Int) {
	inbound = inbound.Add(inbound, big.NewInt(1))
}

package main

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

func init() {
	log.SetLevel(_loglevel)
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    false,
		FullTimestamp:    true,
		PadLevelText:     true,
		ForceQuote:       true,
		QuoteEmptyFields: true,
		TimestampFormat:  time.RFC3339Nano,
	})
	log.SetReportCaller(true)
}
func main() {
	switch err := db_read(); err == nil {
	case true:
		switch err = db_use(); err == nil {
		case true:
			switch err = config_upload(); err == nil {
			case true:
				switch err = config_test(); err == nil {
				case true:
				default:
					log.Fatalf("config test error: '%v'", err)
					return
				}
			default:
				log.Fatalf("config upload error: '%v'", err)
				return
			}
		default:
			log.Fatalf("DB use error: '%v'", err)
			return
		}
	default:
		log.Fatalf("DB read error: '%v'", err)
		return
	}
}

func tabber(inbound string, tabs int) string {
	var (
		in_lenght  = len(inbound)
		tab_lenght = 8
		max_lenght = tabs*tab_lenght - 1
	)
	switch {
	case in_lenght > max_lenght:
		return inbound[:max_lenght]
	case in_lenght < max_lenght:
		var (
			add_tabs string
		)
		for counter := max_lenght - in_lenght - tab_lenght; counter >= 0; counter -= tab_lenght {
			add_tabs += "\t"
		}
		return inbound + add_tabs
	default:
		return inbound
	}
}
func get_vi_ipprefix(vi_shift _VI_ID, peer_shift _VI_Peer_ID) netip.Prefix {
	var (
		b = make([]byte, 4)
	)
	// binary.BigEndian.PutUint32(b, uint32(vi_ip_shift)+uint32(vi_shift)*4+uint32(peer_shift))
	binary.BigEndian.PutUint32(b, uint32(vi_ip_shift+vi_shift*4)+uint32(peer_shift))
	return netip.PrefixFrom(parse_interface(netip.AddrFromSlice(b)).(netip.Addr), 30)
}
func set_vi_ipprefix(inbound netip.Prefix) {
	switch inbound.IsValid() {
	case true:
		vi_ipprefix = inbound
	default:
		switch candidate, err := netip.ParsePrefix(_default_vi_ipprefix); err == nil {
		case true:
			vi_ipprefix = candidate
		default:
			return
		}
	}
	vi_ip_shift = _VI_ID(binary.BigEndian.Uint32(vi_ipprefix.Addr().AsSlice()))
}
func sum_uint32_gt_fm(inbound ...uint32) (outbound uint32) {
	switch len(inbound) {
	case 0:
		return 0
	case 1:
		return inbound[0]
	}
	for index := 0; index < len(inbound); index++ {
		outbound += inbound[index]
	}
	return
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
		case _RI_Name:
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
func ab_create_set(inbound _AB_Name) {
	switch _, flag := pdb_ab[inbound]; flag {
	case true:
		log.Warnf("AB '%v' already exist; ACTION: skip.", inbound)
	}
	pdb_ab[inbound] = _AB{
		Type:     _AB_Type_set,
		AB:       map[_AB_Name]bool{},
		FQDN:     map[_FQDN]bool{},
		IPPrefix: map[netip.Prefix]bool{},
	}
}

func ab_add(public, private bool, ab_name _AB_Name, inbound ...interface{}) {
	var (
		interim []interface{}
		// outbound []interface{}
	)
	for _, address := range inbound {
		var (
			bits = 32
		)
		switch value := (address).(type) {
		case netip.Addr:
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
			case true:
				log.Debugf("AB '%v', address '%v' is valid '%v' against public '%v' / private '%v': address not suitable; ACTION: skip.", ab_name, value, value.IsValid(), public, private)
				continue
			}
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
			interim = append(interim, value)
		case _AB_Name:
			interim = append(interim, value)
		default:
			log.Warnf("AB '%v', address '%v'; unknown address type; ACTION: skip.", ab_name, value)
			continue
		}
	}

	for _, address := range interim {
		switch _, flag := pdb_ab[ab_name]; {
		case flag && pdb_ab[ab_name].Type == _AB_Type_set:
			switch value := (address).(type) {
			case _AB_Name:
				pdb_ab[ab_name].AB[value] = true
			case _FQDN:
				pdb_ab[ab_name].FQDN[value] = true
				ab_add(true, true, _AB_Name(value.String()), value)
				// pdb_ab[_AB_Name(value.String())] = _AB{
				// 	Type: _AB_Type_fqdn,
				// 	FQDN: map[_FQDN]bool{
				// 		value: true,
				// 	},
				// }
			case netip.Prefix:
				pdb_ab[ab_name].IPPrefix[value] = true
				ab_add(true, true, _AB_Name(value.String()), value)
				// pdb_ab[_AB_Name(value.String())] = _AB{
				// 	Type: _AB_Type_ipprefix,
				// 	IPPrefix: map[netip.Prefix]bool{
				// 		value: true,
				// 	},
				// }
			}
		case flag:
			log.Warnf("AB '%v', already exist; ACTION: skip.", ab_name)
			continue
		default:
			switch value := (address).(type) {
			case _FQDN:
				pdb_ab[ab_name] = _AB{
					Type: _AB_Type_fqdn,
					// FQDN: map[_FQDN]bool{
					// 	value: true,
					// },
					Address: value,
				}
			case netip.Prefix:
				pdb_ab[ab_name] = _AB{
					Type: _AB_Type_ipprefix,
					// IPPrefix: map[netip.Prefix]bool{
					// 	value: true,
					// },
					Address: value,
				}
			}
		}
	}
}
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
func log_setlevel(inbound ...*string) {
	switch len(inbound) > 0 {
	case true:
		switch loglevel, err := log.ParseLevel(*inbound[0]); err == nil {
		case true:
			log.SetLevel(loglevel)
		default:
			log.SetLevel(_default_loglevel)
			// log.Warnf("verbosity level '%v' is not supported; ACTION: use '%v'.", *inbound[0], log.GetLevel())
		}
	default:
		log.SetLevel(_loglevel)
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

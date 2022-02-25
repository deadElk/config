package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

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

func read_GT() (err error) {
	var (
		dentry []os.DirEntry
		data   []byte
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
		switch _, flag := pdb_gt[tname]; flag {
		case true:
			log.Warnf("template '%v' already exist; ACTION: skip.", tname)
			continue
		}
		pdb_gt[tname] = pDB_GT{
			Content: _Content(data)._Sanitize(),
		}
	}
	return
}

func _Application_create(ap_name _Name, term []_Security_Application_Term) (ok bool) {
	switch _, flag := pdb_appl[ap_name]; flag {
	case true:
		log.Warnf("Application '%v' already exist; ACTION: skip.", ap_name)
	}
	var (
		c []_Security_Application_Term
	)
	for _, b := range term {
		c = append(c, b)
	}
	ok = true
	pdb_appl[ap_name] = c
	return
}

func _SZ_create(outbound *map[_Name]pDB_Peer_Security_Zone_SZ, sz_name _Name, inbound interface{}) (ok bool) {
	switch value := (inbound).(type) {
	case sDB_Peer_Security_Zone_SZ:
		switch _, flag := (*outbound)[value.Name]; flag {
		case true:
			log.Warnf("SZ '%v' already defined; ACTION: skip.", value.Name)
			return
		}
		(*outbound)[value.Name] = pDB_Peer_Security_Zone_SZ{
			Screen:                value.Screen,
			IF:                    map[_Name]pDB_Peer_Security_Zone_SZ_IF{},
			_Host_Inbound_Traffic: _Host_Inbound_Traffic{},
			_Service_Attributes:   value._Service_Attributes,
		}
		return true
	case pDB_Peer_Security_Zone_SZ:
		switch _, flag := (*outbound)[sz_name]; flag {
		case true:
			log.Warnf("SZ '%v' already defined; ACTION: skip.", sz_name)
			return
		}
		(*outbound)[sz_name] = pDB_Peer_Security_Zone_SZ{
			Screen:                "",
			IF:                    map[_Name]pDB_Peer_Security_Zone_SZ_IF{},
			_Host_Inbound_Traffic: _Host_Inbound_Traffic{},
			_Service_Attributes:   _Service_Attributes{},
		}
		return true
	}
	log.Warnf("don't know what to do with inbound '%+v'; ACTION: skip.", inbound)
	return
}

func _AB_Set_create(ab_name _Name) (ok bool) {
	switch _, flag := pdb_ab[ab_name]; flag {
	case true:
		log.Warnf("AB '%+v''%+v', already exist; ACTION: skip.", ab_name, pdb_ab[ab_name])
		return
	}
	ok = true
	pdb_ab[ab_name] = _Security_AB{
		Address:             nil,
		Type:                _Type_set,
		Addresses:           map[_Name]_Type{},
		_Service_Attributes: _Service_Attributes{},
	}
	return
}
func _AB_Address_add(public, private bool, ab_name _Name, inbound ...interface{}) (ok bool) {
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
		switch _, flag := pdb_ab[ab_name]; {
		case flag && pdb_ab[ab_name].Type == _AB_Type_set:
			switch value := (address).(type) {
			case _Name:
				ok = true
				pdb_ab[ab_name].Addresses[value] = _AB_Type_set
			case _FQDN:
				ok = true
				pdb_ab[ab_name].Addresses[value._Name()] = _AB_Type_fqdn
				_AB_Address_add(true, true, value._Name(), value)
			case netip.Prefix:
				var (
					ab = _Name(value.String())
				)
				ok = true
				pdb_ab[ab_name].Addresses[ab] = _AB_Type_ipprefix
				_AB_Address_add(true, true, ab, value)
			}
		case flag:
			log.Warnf("AB '%+v''%+v', already exist; ACTION: skip.", ab_name, pdb_ab[ab_name])
			continue
		default:
			switch value := (address).(type) {
			case _FQDN:
				ok = true
				pdb_ab[ab_name] = _Security_AB{
					Type:    _AB_Type_fqdn,
					Address: value,
				}
			case netip.Prefix:
				ok = true
				pdb_ab[ab_name] = _Security_AB{
					Type:    _AB_Type_ipprefix,
					Address: value,
				}
			}
		}
	}
	return
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
func set_loglevel(inbound ...string) {
	switch len(inbound) == 1 {
	case true:
		switch loglevel, err := log.ParseLevel(inbound[0]); err == nil {
		case true:
			log.SetLevel(loglevel)
		default:
			log.SetLevel(_Defaults[loglevel].(log.Level))
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

func _AB_rparse(_v_AB_list map[_Name]bool) (outbound map[_Name]bool) {
	outbound = make(map[_Name]bool)
	for a := range _v_AB_list {
		switch {
		case pdb_ab[a].Type != _AB_Type_set:
			outbound[a] = true
		default:
			_AB_rparse_set(&outbound, a)
		}
	}
	return
}
func _AB_rparse_set(_v_AB_list *map[_Name]bool, a _Name) (ok bool) {
	(*_v_AB_list)[a] = true
	for c, d := range pdb_ab[a].Addresses {
		switch {
		case d != _AB_Type_set:
			(*_v_AB_list)[c] = true
		case !(*_v_AB_list)[c]:
			_AB_rparse_set(_v_AB_list, c)
		}
	}
	return
}

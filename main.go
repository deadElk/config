package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io/fs"
	"io/ioutil"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	// "golang.org/x/crypto/ssh"
)

// TODO: implement Junos $1$ (md5/sha1? user passwords), $6$, $9$ (sha? user passwords and PSKs) and other encryption methods
// TODO: implement DB validation and maximum possible autofill

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
	binary.BigEndian.PutUint32(b, uint32(vi_ip_shift)+uint32(vi_shift)*4+uint32(peer_shift))
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
func add_to_ab(public, private bool, ab_name _AB_Name, ip ...interface{}) {
	for _, address := range ip {
		var (
			interim netip.Prefix
			bits    = 32
		)
		switch value := (address).(type) {
		case netip.Addr:
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
			case true:
				continue
			}
			switch value.Is6() {
			case true:
				bits = 128
			}
			interim, _ = value.Prefix(bits)
		case netip.Prefix:
			switch value.IsValid() {
			case false:
				continue
			}
			interim = value
		case string:
			continue
		default:
			continue
		}
		switch _, flag := pdb_ab[ab_name]; flag {
		case false:
			// ab[ab_name] = make(map[netip.Prefix]bool)
			pdb_ab[ab_name] = map[netip.Prefix]bool{
				interim: true,
			}
			continue
		}
		switch _, flag := pdb_ab[ab_name][interim]; flag {
		case false:
			pdb_ab[ab_name][interim] = true
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
func init() {
	log.SetLevel(_loglevel)
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    false,
		FullTimestamp:    true,
		PadLevelText:     true,
		ForceQuote:       true,
		QuoteEmptyFields: true,
		TimestampFormat:  time.RFC3339Nano,
		// TimestampFormat: "02 15:04:05 MST",
	})
	log.SetReportCaller(true)
}
func main() {
	switch err := db_read(); err == nil {
	case true:
		switch err = db_use(); err == nil {
		case true:
			// log.Infof("'%s'", config[4200240063])
			// log.Infof("'%+v'", pdb_vi)
			// log.Infof("'%+v'", pdb_peer[4200240062])
			// log.Infof("'%+v'", pdb_gt)
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
func db_read() (err error) {
	var (
		configuration_files = []string{
			"./" + _serviced + ".xml",
			"/usr/local/opt/etc/" + _serviced + ".xml",
			"/opt/etc/" + _serviced + ".xml",
			"/usr/local/etc/" + _serviced + ".xml",
			"/etc/" + _serviced + ".xml",
		}
		xml_db sDB
		data   []byte
	)
	for _, value := range configuration_files {
		switch data, err = os.ReadFile(value); err == nil {
		case true:
			switch err = xml.Unmarshal(data, &xml_db); err == nil {
			case true:
				log.Debugf("configuration file '%v' loaded.", value)
				log_setlevel(&xml_db.Verbosity)
				set_vi_ipprefix(xml_db.VI_IPPrefix)
				domain_name = xml_db.Domain_Name
				// for _, peer := range xml_db.Peer {
				// 	switch peer.ASN == 4200240062 {
				// 	case true:
				// 		log.Infof("'%+v'", peer.Secutiry)
				// 	}
				// }
				// log.Infof("'%+v'", xml_db.AB)
				// log.Infof("'%+v'", xml_db.Application)
				// log.Exit(1)
				switch len(xml_db.Upload_Path) == 0 {
				case false:
					fs_path["upload"] = xml_db.Upload_Path
				}
				switch len(xml_db.Templates_Path) == 0 {
				case false:
					fs_path["templates"] = xml_db.Templates_Path
				}
				var (
					dentry []fs.DirEntry
				)
				switch dentry, err = os.ReadDir(fs_path["templates"]); err == nil {
				case true:
					for _, fentry := range dentry {
						switch fentry.Type().IsRegular() {
						case true:
							var (
								fsplit = re_dot.Split(fentry.Name(), -1)
							)
							switch len(fsplit) < 1 {
							case false:
								switch fsplit[len(fsplit)-1] == "tmpl" {
								case true:
									var (
										tname = _GT_Name(fentry.Name()[:len(fentry.Name())-5])
									)
									switch data, err = os.ReadFile(fs_path["templates"] + "/" + fentry.Name()); err == nil {
									case true:
										switch _, flag := pdb_gt[tname]; flag {
										case true:
											log.Warnf("template '%v' already exist; ACTION: skip.", tname)
											continue
										}
										pdb_gt[tname] = pDB_GT{
											Content: _GT_Content(data)._Sanitize(),
										}
									}
								}
							}
						}
					}
				}
				switch err = db_parse(&xml_db); err == nil {
				case true:
					log.Debugf("DB '%v' parsed.", xml_db.XMLName)
					return nil
				case false:
					log.Warnf("configuration file '%v' DB parse error: '%v'; ACTION: skip.", value, err)
				}
			default:
				log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", value, err)
			}
		default:
			log.Warnf("file '%v' read error: '%v'; ACTION: skip.", value, err)
		}
	}
	return errors.New("no configuration found")
}
func db_parse(xml_db *sDB) (err error) {
	for _, value := range xml_db.Peer {
		switch _, flag := pdb_peer[value.ASN]; flag {
		case true:
			log.Warnf("peer ASN '%v' already exist; ACTION: skip.", value.ASN)
			continue
		}
		var (
			v_IP_List  = make(map[netip.Prefix]bool)
			vASN_PName = value.ASN._Sanitize()
			vHostname  = func() (outbound _FQDN) {
				switch len(value.Hostname) == 0 {
				case true:
					outbound = _FQDN("gw_as" + vASN_PName.String())
					log.Warnf("peer ASN '%v' hostname not defined; ACTION: use '%v'.", value.ASN, outbound)
					return
				}
				return value.Hostname
			}()
			vGT_List = func() (outbound []_GT_Name) {
				var (
					interim string
				)
				switch len(value.GT_List) == 0 {
				case true:
					interim = xml_db.GT_List + ",AS" + vASN_PName.String()
				default:
					interim = value.GT_List
				}
				var (
					list = re_period.Split(interim, -1)
				)
				for _, list_v := range list {
					switch _, flag := pdb_gt[_GT_Name(list_v)]; flag {
					case true:
						switch pdb_gt[_GT_Name(list_v)].Reserved {
						case false:
							outbound = append(outbound, _GT_Name(list_v))
						default:
							log.Warnf("peer ASN '%v' reserved template '%v' cannot be used; ACTION: skip.", value.ASN, list_v)
							continue
						}
					default:
						log.Warnf("peer ASN '%v', template '%v' not found; ACTION: skip.", value.ASN, list_v)
						continue
					}
				}
				return
			}()
			vMajor = func() float64 {
				var (
					interim = re_caps.Split(value.Version, -1)
				)
				return parse_interface(strconv.ParseFloat(interim[0], 64)).(float64)
			}()
			vRouter_ID netip.Addr
			vIF_RI     = make(map[_IF_Name]_RI_Name)
			vRI        = func() (outbound map[_RI_Name]pDB_Peer_RI) {
				var (
					vIP_IF = make(map[netip.Addr]_IF_Name)
				)
				outbound = make(map[_RI_Name]pDB_Peer_RI)
				for _, ri_v := range value.RI {
					outbound[ri_v.Name] = pDB_Peer_RI{
						RT: func() (rt_o map[netip.Prefix]pDB_Peer_RI_RT) {
							rt_o = make(map[netip.Prefix]pDB_Peer_RI_RT)
							for _, rt_v := range ri_v.RT {
								switch _, flag := rt_o[rt_v.Identifier]; flag {
								case true:
									log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v' already defined; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier)
									continue
								}
								rt_o[rt_v.Identifier] = pDB_Peer_RI_RT{
									GW: func() (gw_o map[_GW_Name]pDB_Peer_RI_RT_GW) {
										gw_o = make(map[_GW_Name]pDB_Peer_RI_RT_GW)
										for _, gw_v := range rt_v.GW {
											var (
												gw_i = strconv.FormatUint(uint64(gw_v.Metric), 10) + "_"
											)
											switch {
											case gw_v.Type == _gw_discard:
												gw_i += _gw_discard.String()
											case gw_v.Type == _gw_hop && gw_v.IP.IsValid():
												gw_i += gw_v.IP.String()
											case gw_v.Type == _gw_interface && len(gw_v.IF) != 0:
												gw_i += gw_v.IF.String()
											case gw_v.Type == _gw_table && len(gw_v.Table) != 0:
												gw_i += gw_v.Table
											case len(gw_v.Type) == 0:
												switch {
												case gw_v.Discard:
													gw_i += _gw_discard.String()
													gw_v.Type = _gw_discard
												case gw_v.IP.IsValid():
													gw_i += gw_v.IP.String()
													gw_v.Type = _gw_hop
												case len(gw_v.IF) != 0:
													gw_i += gw_v.IF.String()
													gw_v.Type = _gw_interface
												case len(gw_v.Table) != 0:
													gw_i += gw_v.Table
													gw_v.Type = _gw_table
												default:
													log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', no gateway found; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier)
													continue
												}
											default:
												log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', unknown gateway type '%v'; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier, gw_v.Type)
												continue
											}
											switch _, flag := gw_o[_GW_Name(gw_i)]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', gateway '%v' already defined; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier, gw_i)
												continue
											}
											gw_o[_GW_Name(gw_i)] = pDB_Peer_RI_RT_GW{
												IP:                  gw_v.IP,
												IF:                  gw_v.IF,
												Table:               gw_v.Table,
												Discard:             gw_v.Discard,
												Type:                gw_v.Type,
												Route_Attributes:    gw_v.Route_Attributes,
												_service_attributes: gw_v._service_attributes,
											}
										}
										return
									}(),
									_service_attributes: rt_v._service_attributes,
								}
							}
							return
						}(),
						IF: func() (if_o map[_IF_Name]pDB_Peer_RI_IF) {
							if_o = make(map[_IF_Name]pDB_Peer_RI_IF)
							for _, if_v := range ri_v.IF {
								switch if_ri_v, flag := vIF_RI[if_v.Name]; flag {
								case true:
									log.Warnf("peer ASN '%v', RI '%v', IF '%v' already defined in RI '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, if_ri_v)
									continue
								}
								vIF_RI[if_v.Name] = ri_v.Name
								var (
									if_o_Major string
									if_o_Minor string
								)
								func() {
									var (
										interim = re_dot.Split(if_v.Name.String(), -1)
									)
									if_o_Major = interim[0]
									if_o_Minor = interim[1]
								}()
								if_o[if_v.Name] = pDB_Peer_RI_IF{
									Communication: if_v.Communication._Sanitize(_if_mode_link),
									Major:         if_o_Major,
									Minor:         if_o_Minor,
									IP: func() (ip_o map[netip.Addr]pDB_Peer_RI_IF_IP) {
										ip_o = make(map[netip.Addr]pDB_Peer_RI_IF_IP)
										for _, ip_v := range if_v.IP {
											switch ip_v.IPPrefix.IsValid() || ip_v.DHCP {
											case false:
												log.Warnf("peer ASN '%v', RI '%v', IF '%v', invalid IPPrefix '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, ip_v.IPPrefix)
												continue
											}
											var (
												ip_i = ip_v.IPPrefix.Addr()
											)
											switch ip_if_v, flag := vIP_IF[ip_i]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', IF '%v', IP '%v' already defined in IF '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, ip_i, ip_if_v)
												continue
											}
											vIP_IF[ip_i] = if_v.Name
											switch ip_v.Router_ID {
											case true:
												switch vRouter_ID.IsValid() {
												case false:
													vRouter_ID = ip_i
												default:
													log.Warnf("peer ASN '%v', router ID '%v' already defined; ACTION: skip.", value.ASN, vRouter_ID)
												}
											}
											add_to_ab(true, false, "OUTTER_LIST", ip_v.IPPrefix.Addr(), ip_v.NAT)
											switch {
											case ip_v.NAT.IsValid() && !ip_v.NAT.IsPrivate():
												v_IP_List[parse_interface(ip_v.NAT.Prefix(32)).(netip.Prefix)] = true
											case ip_v.IPPrefix.IsValid() && !ip_v.IPPrefix.Addr().IsPrivate():
												v_IP_List[ip_v.IPPrefix] = true
											case ip_v.IPPrefix.IsValid():
												v_IP_List[ip_v.IPPrefix] = false
											}
											ip_o[ip_i] = pDB_Peer_RI_IF_IP{
												IPPrefix:            ip_v.IPPrefix,
												Masked:              ip_v.IPPrefix.Masked(),
												Router_ID:           ip_v.Router_ID,
												Primary:             ip_v.Primary,
												Preferred:           ip_v.Preferred,
												NAT:                 ip_v.NAT,
												DHCP:                ip_v.DHCP,
												_service_attributes: ip_v._service_attributes,
											}
										}
										return
									}(),
									PARP: func() (parp_o map[netip.Addr]pDB_Peer_RI_IF_PARP) {
										parp_o = make(map[netip.Addr]pDB_Peer_RI_IF_PARP)
										for _, parp_v := range if_v.PARP {
											var (
												parp_i = parp_v.IPPrefix.Addr()
											)
											switch ip_if_v, flag := vIP_IF[parp_i]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', IF '%v', Proxy_ARP IP '%v' already defined in IF '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, parp_i, ip_if_v)
												continue
											}
											vIP_IF[parp_i] = if_v.Name
											add_to_ab(true, false, "OUTTER_LIST", parp_v.IPPrefix.Addr(), parp_v.NAT)
											parp_o[parp_v.IPPrefix.Addr()] = pDB_Peer_RI_IF_PARP{
												IPPrefix:            parp_v.IPPrefix,
												NAT:                 parp_v.NAT,
												_service_attributes: parp_v._service_attributes,
											}
										}
										return
									}(),
									Disable: if_v.Disable,
									Host_Inbound_Traffic: Host_Inbound_Traffic{
										Services: map[_Service]bool{
											_service_all:         false,
											_service_any_service: false,
											_service_bootp:       false,
											_service_dhcp:        false,
											_service_dhcpv6:      false,
											_service_ike:         false,
											_service_ping:        true,
											_service_snmp:        false,
											_service_snmp_trap:   false,
											_service_ssh:         true,
											_service_traceroute:  true,
										},
										Protocols: map[_Protocol]bool{
											_protocol_all: false,
											_protocol_bgp: false,
										},
									},
									// Services: _Service_List{
									// 	_service_all:         default_services[_service_all],
									// 	_service_any_service: default_services[_service_any_service],
									// 	_service_bootp:       default_services[_service_bootp],
									// 	_service_dhcp:        default_services[_service_dhcp],
									// 	_service_dhcpv6:      default_services[_service_dhcpv6],
									// 	_service_ike:         default_services[_service_ike],
									// 	_service_ping:        default_services[_service_ping],
									// 	_service_snmp:        default_services[_service_snmp],
									// 	_service_snmp_trap:   default_services[_service_snmp_trap],
									// 	_service_ssh:         default_services[_service_ssh],
									// 	_service_traceroute:  default_services[_service_traceroute],
									// },
									// Protocols: _Protocol_List{
									// 	_protocol_all: default_protocols[_protocol_all],
									// 	_protocol_bgp: default_protocols[_protocol_bgp],
									// },
									_service_attributes: if_v._service_attributes,
								}
							}
							return
						}(),
						IP_IF:                vIP_IF,
						Policy:               ri_v.Policy._Sanitize(),
						Host_Inbound_Traffic: Host_Inbound_Traffic{},
						_service_attributes: _service_attributes{
							Reserved: ri_v.Reserved,
							Description: func() _Description {
								switch ri_v.Name == _juniper_mgmt_RI && len(ri_v.Description) == 0 {
								case true:
									return _juniper_mgmt_Description
								}
								return ri_v.Description
							}(),
							// Verbosity: ri_v.Verbosity,
						},
					}
				}
				return
			}()
			v_IFM = func() (outbound map[_IFM_Name]pDB_Peer_IFM) {
				outbound = make(map[_IFM_Name]pDB_Peer_IFM)
				for _, ifm_v := range value.IFM {
					outbound[ifm_v.Name] = pDB_Peer_IFM{
						Communication:       ifm_v.Communication,
						Disable:             ifm_v.Disable,
						_service_attributes: ifm_v._service_attributes,
					}
				}
				return
			}()
			v_Domain_Name = func() _FQDN {
				switch len(value.Domain_Name) == 0 {
				case true:
					return domain_name
				}
				return value.Domain_Name
			}()
		)
		pdb_peer[value.ASN] = pDB_Peer{
			ASN:                 value.ASN,
			ASN_PName:           vASN_PName,
			Router_ID:           vRouter_ID,
			IFM:                 v_IFM,
			RI:                  vRI,
			IF_RI:               vIF_RI,
			Hostname:            vHostname,
			Domain_Name:         v_Domain_Name,
			Version:             value.Version,
			Major:               vMajor,
			IKE_GCM:             vMajor >= 12.3,
			Manufacturer:        value.Manufacturer,
			Model:               value.Model,
			Serial:              value.Serial,
			Root:                value.Root._Sanitize(16, "peer AS"+vASN_PName.String()+": root password is not acceptable"),
			GT_List:             vGT_List,
			VI:                  map[_VI_ID]pDB_Peer_VI{},
			RM_ID:               &rm_id,
			AB:                  &ab,
			IPPrefix_List:       v_IP_List,
			_service_attributes: value._service_attributes,
		}
	}

	for _, value := range xml_db.VI {
		switch value.Reserved {
		case true:
			continue
		}
		var (
			peers = len(value.Peer)
		)
		switch peers == 2 {
		case false:
			log.Warnf("VI '%v', wrong total peers number '%v'; ACTION: skip.", value.ID, peers)
			continue
		}
		func() {
			var (
				v_No_NAT = true
				v_NAT    = make([]netip.Addr, peers)
			)
			for peer_index := range value.Peer {
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN]; flag {
				case false:
					log.Warnf("VI '%v', ASN '%v', peer '%v' not defined; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, peer_index)
					return
				}
				switch value.Peer[peer_index].Reserved {
				case true:
					log.Warnf("VI '%v', ASN '%v', peer '%v' reserved; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, peer_index)
					return
				}
				value.Peer[peer_index].RI = value.Peer[peer_index].RI._Sanitize(_juniper_mgmt_RI)
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI]; flag {
				case false:
					log.Warnf("VI '%v', ASN '%v', RI '%v' not defined; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, value.Peer[peer_index].RI)
					return
				}
				value.Peer[peer_index].Inner_RI = value.Peer[peer_index].Inner_RI._Sanitize(_juniper_mgmt_RI)
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].Inner_RI]; flag {
				case false:
					log.Warnf("VI '%v', ASN '%v', inner RI '%v' not defined; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, value.Peer[peer_index].Inner_RI)
					return
				}
				switch len(value.Peer[peer_index].IF) == 0 {
				case true:
					for if_i := range pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF {
						value.Peer[peer_index].IF = if_i
						log.Debugf("VI '%v', peer '%v', no interface defined; ACTION: found '%v'.", value.ID.String(), peer_index, value.Peer[peer_index].IF)
						break
					}
				case false:
					switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF]; flag {
					case false:
						log.Warnf("VI '%v', ASN '%v', RI '%v', IF '%v' not defined; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, value.Peer[peer_index].RI, value.Peer[peer_index].IF)
						return
					}
				}
				switch value.Peer[peer_index].IP.String() == "invalid IP" {
				case true:
					for ip_i := range pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].IP {
						value.Peer[peer_index].IP = ip_i
						log.Debugf("VI '%v', peer '%v', no IP defined; ACTION: found '%v'.", value.ID.String(), peer_index, value.Peer[peer_index].IP)
						break
					}
				}
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].IP[value.Peer[peer_index].IP]; flag {
				case false:
					log.Warnf("VI '%v', ASN '%v' RI '%v' IF '%v' IP '%v' not found; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, value.Peer[peer_index].RI, value.Peer[peer_index].IF, value.Peer[peer_index].IP)
					return
				}
				switch nat := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].IP[value.Peer[peer_index].IP].NAT; nat.IsValid() {
				case true:
					v_NAT[peer_index] = nat
				case false:
					v_NAT[peer_index] = value.Peer[peer_index].IP
				}
				switch v_NAT[peer_index].IsValid() {
				case false:
					log.Warnf("VI '%v', peer '%v' no valid outter IP found; ACTION: skip.", value.ID, peer_index)
					return
				}
				switch v_NAT[peer_index].IsPrivate() {
				case true:
					log.Warnf("VI '%v', peer '%v' no public outter IP found; ACTION: use IKE NAT traversal.", value.ID, peer_index)
					v_No_NAT = false
				}
				pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].Services[_service_ike] = true
			}
			var (
				v_Metric = func() uint {
					switch value.Route_Metric > _rm_max {
					case true:
						return 0
					}
					return _rm_max - value.Route_Metric
				}()
				v_Left_Inner_IPPrefix  = get_vi_ipprefix(value.ID, 1)
				v_Right_Inner_IPPrefix = get_vi_ipprefix(value.ID, 2)
			)
			pdb_peer[value.Peer[0].ASN].VI[value.ID] = pDB_Peer_VI{
				VI_ID_PName:          value.ID._Sanitize(),
				Type:                 value.Type._Sanitize(),
				Communication:        value.Communication._Sanitize(_if_mode_vi),
				PSK:                  value.PSK._Sanitize(64),
				Route_Metric:         v_Metric,
				IPPrefix:             get_vi_ipprefix(value.ID, 0),
				No_NAT:               v_No_NAT,
				IKE_GCM:              pdb_peer[value.Peer[0].ASN].IKE_GCM && pdb_peer[value.Peer[1].ASN].IKE_GCM,
				Left_ASN:             value.Peer[0].ASN,
				Left_RI:              value.Peer[0].RI,
				Left_IF:              value.Peer[0].IF,
				Left_IP:              value.Peer[0].IP,
				Left_NAT:             v_NAT[0],
				Left_Local_Address:   len(pdb_peer[value.Peer[0].ASN].RI[value.Peer[0].RI].IF[value.Peer[0].IF].IP) > 1,
				Left_Dynamic:         value.Peer[0].Dynamic,
				Left_Hub:             value.Peer[0].Hub,
				Left_Inner_RI:        value.Peer[0].Inner_RI._Sanitize(_juniper_mgmt_RI),
				Left_Inner_IP:        v_Left_Inner_IPPrefix.Addr(),
				Left_Inner_IPPrefix:  v_Left_Inner_IPPrefix,
				Right_ASN:            value.Peer[1].ASN,
				Right_RI:             value.Peer[1].RI,
				Right_IF:             value.Peer[1].IF,
				Right_IP:             value.Peer[1].IP,
				Right_NAT:            v_NAT[1],
				Right_Local_Address:  len(pdb_peer[value.Peer[1].ASN].RI[value.Peer[1].RI].IF[value.Peer[1].IF].IP) > 1,
				Right_Dynamic:        value.Peer[1].Dynamic,
				Right_Hub:            value.Peer[1].Hub,
				Right_Inner_RI:       value.Peer[1].Inner_RI._Sanitize(_juniper_mgmt_RI),
				Right_Inner_IP:       v_Right_Inner_IPPrefix.Addr(),
				Right_Inner_IPPrefix: v_Right_Inner_IPPrefix,
				_service_attributes:  value._service_attributes,
			}
			pdb_peer[value.Peer[1].ASN].VI[value.ID] = pDB_Peer_VI{
				VI_ID_PName:          pdb_peer[value.Peer[0].ASN].VI[value.ID].VI_ID_PName,
				Type:                 pdb_peer[value.Peer[0].ASN].VI[value.ID].Type,
				Communication:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Communication,
				PSK:                  pdb_peer[value.Peer[0].ASN].VI[value.ID].PSK,
				Route_Metric:         pdb_peer[value.Peer[0].ASN].VI[value.ID].Route_Metric,
				IPPrefix:             pdb_peer[value.Peer[0].ASN].VI[value.ID].IPPrefix,
				No_NAT:               pdb_peer[value.Peer[0].ASN].VI[value.ID].No_NAT,
				IKE_GCM:              pdb_peer[value.Peer[0].ASN].VI[value.ID].IKE_GCM,
				Left_ASN:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_ASN,
				Left_RI:              pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_RI,
				Left_IF:              pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_IF,
				Left_IP:              pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_IP,
				Left_NAT:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_NAT,
				Left_Local_Address:   pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Local_Address,
				Left_Dynamic:         pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Dynamic,
				Left_Hub:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Hub,
				Left_Inner_RI:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Inner_RI,
				Left_Inner_IP:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Inner_IP,
				Left_Inner_IPPrefix:  pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Inner_IPPrefix,
				Right_ASN:            pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_ASN,
				Right_RI:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_RI,
				Right_IF:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_IF,
				Right_IP:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_IP,
				Right_NAT:            pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_NAT,
				Right_Local_Address:  pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Local_Address,
				Right_Dynamic:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Dynamic,
				Right_Hub:            pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Hub,
				Right_Inner_RI:       pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Inner_RI,
				Right_Inner_IP:       pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Inner_IP,
				Right_Inner_IPPrefix: pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Inner_IPPrefix,
				_service_attributes:  pdb_peer[value.Peer[0].ASN].VI[value.ID]._service_attributes,
			}
		}()
	}
	return
}
func db_use() (err error) {
	for index, value := range pdb_peer {
		switch value.Reserved {
		case false:
			for _, gt_v := range value.GT_List {
				var (
					vGT_name = gt_v.String()
					vGT      *template.Template
					vBuf     bytes.Buffer
				)
				switch vGT, err = template.New(vGT_name).Funcs(gt_fm).Parse(pdb_gt[_GT_Name(vGT_name)].Content.String()); err == nil && vGT != nil {
				case true:
					switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
					case true:
						config[index] = append(config[index], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
					default:
						log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
						continue
					}
				default:
					log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
					continue
				}
			}
			var (
				vGT_name = "AS" + value.ASN_PName.String() + "_GT_Patch"
				vGT      *template.Template
				vBuf     bytes.Buffer
			)
			switch vGT, err = template.New(vGT_name).Funcs(gt_fm).Parse(value.GT_Patch.String()); err == nil && vGT != nil {
			// switch vGT, err = template.New("config.tmpl").Funcs(gt_fm).ParseFiles("config.tmpl"); err == nil && vGT != nil {
			case true:
				switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
				case true:
					config[index] = append(config[index], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
				default:
					log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
					continue
				}
			default:
				log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
				continue
			}
		}
	}
	return
}
func config_test() (err error) {
	return
}
func config_upload() (err error) {
	var (
		hosts   string
		ordered []int
	)
	for index, value := range config {
		ordered = append(ordered, int(index))
		var (
			fn = fs_path["upload"] + "./AS" + index.String()
		)
		switch err_i := os.WriteFile(fn, value, 0600); err_i == nil {
		case true:
			log.Infof("OK '%v'", index)
		case false:
			log.Errorf("Fail '%v' with error '%v'", index, err_i)
		}
	}

	sort.Ints(ordered)
	for _, value := range ordered {
		var (
			index = _ASN(value)
		)
		hosts += func() (outbound string) {
			var (
				ips       string
				publics   []netip.Prefix
				router_id = parse_interface(pdb_peer[index].Router_ID.Prefix(32)).(netip.Prefix)
			)
			publics = append(publics, router_id)
			for ip_i, ip_v := range pdb_peer[index].IPPrefix_List {
				switch ip_i == router_id {
				case false:
					ips += tabber(ip_i.String(), 3) + "\t"
				}
				switch ip_v {
				case true:
					publics = append(publics, ip_i)
				}
			}
			for _, ip := range publics {
				outbound += tabber(ip.Addr().String(), 2) +
					"\t####\t" +
					tabber(pdb_peer[index].ASN_PName.String(), 2) + "\t" +
					tabber(pdb_peer[index].Router_ID.String(), 2) + "\t" +
					tabber(pdb_peer[index].Hostname.String(), 3) + "\t" +
					tabber(pdb_peer[index].Manufacturer+" "+pdb_peer[index].Model, 3) + "\t####\t" +
					// tabber(pdb_peer[index].Manufacturer, 2) + "\t"+
					// tabber(pdb_peer[index].Model, 2) + "\t####\t\t" +
					ips + "\n"
			}
			outbound += "\n"
			return
		}()
	}

	switch err_i := os.WriteFile(fs_path["upload"]+"./hosts.txt", []byte(hosts), 0600); err_i == nil {
	case true:
		log.Infof("OK 'hosts.txt'")
	case false:
		log.Errorf("Fail 'hosts.txt' with error '%v'", err_i)
	}

	// var (
	// 	connections_config_maintain = func(source_url *url.URL) (status bool) {
	// 		switch connections_config[source_url] == nil {
	// 		case true:
	// 			var (
	// 				file_name = func() (outbound string) {
	// 					switch current_user, err := user.Current(); err == nil && current_user != nil {
	// 					case true:
	// 						outbound = current_user.HomeDir
	// 					}
	// 					switch len(outbound) == 0 {
	// 					case true:
	// 						outbound = "~"
	// 					}
	// 					outbound += "/.ssh/" + source_url.User.Username() + "_" + source_url.Hostname() + "_" + source_url.Port() + ".key"
	// 					return
	// 				}()
	// 			)
	// 			switch file_reader, err := os.Open(file_name); err == nil {
	// 			case true:
	// 				defer func() {
	// 					switch file_reader != nil {
	// 					case true:
	// 						log.Debugf("%v: file_reader.Close() status: '%v'", worker.Description, file_reader.Close())
	// 					}
	// 				}()
	// 				switch file_data, err := io.ReadAll(file_reader); err == nil {
	// 				case true:
	// 					switch private_key, err := ssh.ParsePrivateKey(file_data); err == nil {
	// 					case true:
	// 						connections_config[source_url] = &ssh.ClientConfig{
	// 							User:            source_url.User.Username(),
	// 							Auth:            []ssh.AuthMethod{ssh.PublicKeys(private_key)},
	// 							HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	// 							// BannerCallback:    nil,
	// 							// ClientVersion:     nil,
	// 							// HostKeyAlgorithms: nil,
	// 							Timeout: _timeout_worker_retry,
	// 						}
	// 						return true
	// 					default:
	// 						log.Warnf("%v: file '%v' parse error '%v'; ACTION: retry later.", worker.Description, file_name, err)
	// 					}
	// 				default:
	// 					log.Warnf("%v: file '%v' read error '%v'; ACTION: retry later.", worker.Description, file_name, err)
	// 				}
	// 			default:
	// 				log.Warnf("%v: file '%v' open error '%v'; ACTION: retry later.", worker.Description, file_name, err)
	// 			}
	// 		}
	// 		return
	// 	}
	// 	connection_maintain = func(source_url *url.URL) (status bool) {
	// 		switch connections[source_url] == nil {
	// 		case true:
	// 			switch connections_config_maintain(source_url) {
	// 			case true:
	// 				switch connection, err := ssh.Dial("tcp", source_url.Host, connections_config[source_url]); err == nil {
	// 				case true:
	// 					log.Debugf("%v: '%v' connected.", worker.Description, source_url.Redacted())
	// 					connections[source_url] = connection
	// 					return true
	// 				default:
	// 					log.Warnf("%v: '%v' connect error '%v'; ACTION: retry later.", worker.Description, source_url.Redacted(), err)
	// 					connection_terminate(source_url)
	// 				}
	// 			default:
	// 				log.Warnf("%v: ssh options is not available for '%v'; ACTION: retry later.", worker.Description, source_url.Redacted())
	// 			}
	// 		default:
	// 			return true
	// 		}
	// 		return
	// 	}
	// 	send_message = func(incoming_message Message) {
	// 		for _, source_url := range worker.Source {
	// 			switch connection_maintain(source_url) {
	// 			case true:
	// 				switch connection_session, err := connections[source_url].NewSession(); err == nil {
	// 				case true:
	// 					defer func() {
	// 						switch connection_session != nil {
	// 						case true:
	// 							log.Debugf("%v: session.Close() status: '%v'", worker.Description, connection_session.Close())
	// 						}
	// 					}()
	// 					var (
	// 						session_stdout = new(bytes.Buffer)
	// 						session_stderr = new(bytes.Buffer)
	// 					)
	// 					connection_session.Stdin = strings.NewReader(incoming_message.Content[_search_raw])
	// 					connection_session.Stdout = session_stdout
	// 					connection_session.Stderr = session_stderr
	// 					switch err := connection_session.Run("cat > " + source_url.Path + "/" + incoming_message.ID.String() + ".txt"); err == nil {
	// 					case true:
	// 						delete(message_cache, incoming_message.ID)
	// 						counter_counts(string(worker.Description), "cache", -1)
	// 						log.Debugf("%v: message sent using '%v'. data: from '%v' to '%v'; ACTION: remove from a cache.", worker.Description, source_url.Redacted(), incoming_message.Content[_search_from], incoming_message.Content[_search_to])
	// 						return
	// 					default:
	// 						log.Warnf("%v: %v command execution error '%v', stderr '%v', stdout '%v'; ACTION: try next source.", worker.Description, source_url.Redacted(), err, session_stdout.String(), session_stderr.String())
	// 						connection_terminate(source_url)
	// 					}
	// 				default:
	// 					log.Warnf("%v: %v create session error '%v'; ACTION: try next source.", worker.Description, source_url.Redacted(), err)
	// 				}
	// 			}
	// 		}
	// 		log.Warnf("%v: no way to send a message; ACTION: retry later.", worker.Description)
	// 	}
	// )

	log.Infof("\n%s\n", hosts)
	return
}

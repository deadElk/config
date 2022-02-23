package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net/netip"
	_ "net/netip"
	"os"
	"sort"
	"strconv"
	"text/template"

	log "github.com/sirupsen/logrus"
	// "golang.org/x/crypto/ssh"
)

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
				switch len(xml_db.Upload_Path) == 0 {
				case false:
					fs_path["upload"] = xml_db.Upload_Path
				}
				switch len(xml_db.Templates_Path) == 0 {
				case false:
					fs_path["templates"] = xml_db.Templates_Path
				}
				_Templates_read()
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
	return errors.New("nothing to do")
}
func db_parse(xml_db *sDB) (err error) {
	for _, b := range xml_db.AB {
		switch b.Set {
		case true:
			_AB_Set_create(b.Name)
		}
		for _, d := range b.Address {
			_AB_Address_add(true, true, b.Name, d.AB, d.FQDN, d.IPPrefix)
		}
	}
	for _, b := range xml_db.Application {
		_Application_create(b.Name, b.Term)
	}
	for _, value := range xml_db.Peer {
		switch _, flag := pdb_peer[value.ASN]; flag {
		case true:
			log.Warnf("peer ASN '%v' already exist; ACTION: skip.", value.ASN)
			continue
		}
		var (
			v_SZ = make(map[_SZ_Name]pDB_Peer_Security_Zone_SZ)
		)
		for _, b := range value.SZ {
			_SZ_create(&v_SZ, "", b)
		}

		var (
			// _v_AB_list          = make(map[_AB_Name]bool)
			// _v_Application_list = make(map[_Application_Name]bool)
			v_IP_List   = make(map[netip.Prefix]bool)
			v_ASN_PName = value.ASN._Sanitize()
			v_Hostname  = func() (outbound _FQDN) {
				switch len(value.Hostname) == 0 {
				case true:
					outbound = _FQDN("gw_as" + v_ASN_PName.String())
					log.Warnf("peer ASN '%v' hostname not defined; ACTION: use '%v'.", value.ASN, outbound)
					return
				}
				return value.Hostname
			}()
			v_GT_List = func() (outbound []_GT_Name) {
				var (
					interim string
				)
				switch len(value.GT_List) == 0 {
				case true:
					interim = xml_db.GT_List + ",AS" + v_ASN_PName.String()
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
			v_Major = func() float64 {
				var (
					interim = re_caps.Split(value.Version, -1)
				)
				return parse_interface(strconv.ParseFloat(interim[0], 64)).(float64)
			}()
			v_Router_ID netip.Addr
			v_IF_RI     = make(map[_IF_Name]_RI_Name)
			v_RI        = func() (outbound map[_RI_Name]pDB_Peer_RI) {
				var (
					vIP_IF = make(map[netip.Addr]_IF_Name)
				)
				outbound = make(map[_RI_Name]pDB_Peer_RI)
				for _, ri_v := range value.RI {
					switch ri_v.Name == _juniper_mgmt_RI {
					case false:
						_SZ_create(&v_SZ, ri_v.Name._SZ_Name(), pDB_Peer_Security_Zone_SZ{})
					}
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
												gw_i += gw_v.Table.String()
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
													gw_i += gw_v.Table.String()
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
												_Route_Attributes:   gw_v._Route_Attributes,
												_Service_Attributes: gw_v._Service_Attributes,
											}
										}
										return
									}(),
									_Service_Attributes: rt_v._Service_Attributes,
								}
							}
							return
						}(),
						IF: func() (if_o map[_IF_Name]pDB_Peer_RI_IF) {
							if_o = make(map[_IF_Name]pDB_Peer_RI_IF)
							for _, if_v := range ri_v.IF {
								switch if_ri_v, flag := v_IF_RI[if_v.Name]; flag {
								case true:
									log.Warnf("peer ASN '%v', RI '%v', IF '%v' already defined in RI '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, if_ri_v)
									continue
								}
								v_IF_RI[if_v.Name] = ri_v.Name
								var (
									IF_split  = re_dot.Split(if_v.Name.String(), -1)
									if_o_IFM  = _IFM_Name(IF_split[0])
									if_o_IFsM = _IFsM_Name(IF_split[1])
								)
								if_o[if_v.Name] = pDB_Peer_RI_IF{
									Communication: if_v.Communication._Sanitize(_if_mode_link),
									IFM:           if_o_IFM,
									IFsM:          if_o_IFsM,
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
												switch v_Router_ID.IsValid() {
												case false:
													v_Router_ID = ip_i
												default:
													log.Warnf("peer ASN '%v', router ID '%v' already defined; ACTION: skip.", value.ASN, v_Router_ID)
												}
											}
											_AB_Address_add(true, false, "OUTTER_LIST", ip_v.IPPrefix.Addr(), ip_v.NAT)
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
												_Service_Attributes: ip_v._Service_Attributes,
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
											_AB_Address_add(true, false, "OUTTER_LIST", parp_v.IPPrefix.Addr(), parp_v.NAT)
											parp_o[parp_v.IPPrefix.Addr()] = pDB_Peer_RI_IF_PARP{
												IPPrefix:            parp_v.IPPrefix,
												NAT:                 parp_v.NAT,
												_Service_Attributes: parp_v._Service_Attributes,
											}
										}
										return
									}(),
									Disable:             if_v.Disable,
									_Service_Attributes: if_v._Service_Attributes,
								}
								switch ri_v.Name == _juniper_mgmt_RI {
								case false:
									v_SZ[ri_v.Name._SZ_Name()].IF[if_v.Name] = pDB_Peer_Security_Zone_SZ_IF{
										_Host_Inbound_Traffic: _Host_Inbound_Traffic{
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
										_Service_Attributes: _Service_Attributes{},
									}
								}
							}
							return
						}(),
						IP_IF: vIP_IF,
						_Service_Attributes: _Service_Attributes{
							Deactivate: ri_v.Deactivate,
							Reserved:   ri_v.Reserved,
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
						_Service_Attributes: ifm_v._Service_Attributes,
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
		for _, b := range value.AB {
			switch b.Set {
			case true:
				_AB_Set_create(b.Name)
			}
			for _, d := range b.Address {
				_AB_Address_add(true, true, b.Name, d.AB, d.FQDN, d.IPPrefix)
			}
		}
		for _, b := range value.Application {
			_Application_create(b.Name, b.Term)
		}
		pdb_peer[value.ASN] = pDB_Peer{
			ASN:                 value.ASN,
			ASN_PName:           v_ASN_PName,
			Router_ID:           v_Router_ID,
			AB:                  map[_AB_Name]_Security_AB{},
			Application:         map[_Application_Name][]_Security_Application_Term{},
			SZ:                  v_SZ,
			NAT_Source:          value.NAT_Source,
			NAT_Destination:     value.NAT_Destination,
			NAT_Static:          value.NAT_Static,
			Policies_Exact:      value.Policies_Exact,
			Policies_Global:     value.Policies_Global,
			IFM:                 v_IFM,
			RI:                  v_RI,
			IF_RI:               v_IF_RI,
			Hostname:            v_Hostname,
			Domain_Name:         v_Domain_Name,
			Version:             value.Version,
			Major:               v_Major,
			IKE_GCM:             v_Major >= 12.3,
			Manufacturer:        value.Manufacturer,
			Model:               value.Model,
			Serial:              value.Serial,
			Root:                value.Root._Sanitize(16, "peer AS"+v_ASN_PName.String()+": root password is not acceptable"),
			GT_List:             v_GT_List,
			VI:                  map[_VI_ID]pDB_Peer_VI{},
			RM_ID:               &rm_id,
			IPPrefix_List:       v_IP_List,
			_Service_Attributes: value._Service_Attributes,
		}
	}

	for _, value := range pdb_peer {

		var (
			_v_AB_list          = make(map[_AB_Name]bool)
			_v_Application_list = make(map[_Application_Name]bool)
		)
		for _, b := range value.NAT_Source {
			for _, d := range b.Rule_Set {
				for _, x := range d.Rule {
					for _, z := range x.Match {
						switch len(z.AB) == 0 {
						case false:
							_v_AB_list[z.AB] = true
						}
						switch len(z.Application) == 0 {
						case false:
							_v_Application_list[z.Application] = true
						}
					}
				}
			}
		}
		for _, b := range value.NAT_Destination {
			for _, d := range b.Rule_Set {
				for _, x := range d.Rule {
					for _, z := range x.Match {
						switch len(z.AB) == 0 {
						case false:
							_v_AB_list[z.AB] = true
						}
						switch len(z.Application) == 0 {
						case false:
							_v_Application_list[z.Application] = true
						}
					}
				}
			}
		}
		for _, b := range value.Policies_Exact {
			for _, x := range b.Policy {
				for _, z := range x.Match {
					switch len(z.AB) == 0 {
					case false:
						_v_AB_list[z.AB] = true
					}
					switch len(z.Application) == 0 {
					case false:
						_v_Application_list[z.Application] = true
					}
				}
			}
		}
		for _, x := range value.Policies_Global {
			for _, z := range x.Match {
				switch len(z.AB) == 0 {
				case false:
					_v_AB_list[z.AB] = true
				}
				switch len(z.Application) == 0 {
				case false:
					_v_Application_list[z.Application] = true
				}
			}
		}

		_v_AB_list = _AB_rparse(_v_AB_list)

		for a := range _v_AB_list {
			value.AB[a] = pdb_ab[a]
		}
		for a := range _v_Application_list {
			value.Application[a] = pdb_appl[a]
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
				v_Type   = value.Type._Sanitize()
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
				pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].RI._SZ_Name()].IF[value.Peer[peer_index].IF].Services[_service_ike] = true
				pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].Inner_RI._SZ_Name()].IF[_IF_Name(v_Type.String()+"0."+value.ID.String())] = pDB_Peer_Security_Zone_SZ_IF{
					_Host_Inbound_Traffic: _Host_Inbound_Traffic{
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
							_protocol_bgp: true,
						},
					},
					_Service_Attributes: _Service_Attributes{},
				}
				// pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].Inner_RI._SZ_Name()].IF[_IF_Name(v_Type.String()+"0."+value.ID.String())]._Defaults()
				pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].Inner_RI._SZ_Name()].IF[_IF_Name(v_Type.String()+"0."+value.ID.String())].Protocols[_protocol_bgp] = true
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
				Type:                 v_Type,
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
				_Service_Attributes:  value._Service_Attributes,
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
				_Service_Attributes:  pdb_peer[value.Peer[0].ASN].VI[value.ID]._Service_Attributes,
			}
		}()
	}
	return
}
func db_use() (err error) {
	for index, value := range pdb_peer {
		switch value.Reserved {
		case false:
			func() {
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
							return
						}
					default:
						log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
						return
					}
				}
			}()
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
		// log.Errorf("\n\n%v\n\n", pdb_peer[index].SZ)
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

	log.Infof("\n%s\n", hosts)
	return
}

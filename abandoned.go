package main

import (
	"bytes"
	"io/ioutil"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"text/template"

	log "github.com/sirupsen/logrus"
)

// type _Service_List map[_Service]bool
// type _Protocol_List map[_Protocol]bool
// type _Services struct {
// 	All               bool
// 	Any_Service       bool
// 	appqoe            bool
// 	BOOTP             bool
// 	DHCP              bool
// 	DHCPv6            bool
// 	dns               bool
// 	finger            bool
// 	ftp               bool
// 	http              bool
// 	https             bool
// 	ident_reset       bool
// 	IKE               bool
// 	lsping            bool
// 	netconf           bool
// 	ntp               bool
// 	PING              bool
// 	r2cp              bool
// 	reverse_ssh       bool
// 	reverse_telnet    bool
// 	rlogin            bool
// 	rpm               bool
// 	rsh               bool
// 	SNMP              bool
// 	SNMP_Trap         bool
// 	SSH               bool
// 	tcp_encap         bool
// 	telnet            bool
// 	tftp              bool
// 	Traceroute        bool
// 	webapi_clear_text bool
// 	webapi_ssl        bool
// 	xnm_clear_text    bool
// 	xnm_ssl           bool
// }
// type _Protocols struct {
// 	All              bool
// 	bfd              bool
// 	BGP              bool
// 	dvmrp            bool
// 	igmp             bool
// 	ldp              bool
// 	msdp             bool
// 	nhrp             bool
// 	ospf             bool
// 	ospf3            bool
// 	pgm              bool
// 	pim              bool
// 	rip              bool
// 	ripng            bool
// 	router_discovery bool
// 	rsvp             bool
// 	sap              bool
// 	vrrp             bool
// }

// func db_use() (err error) {
// var (
// 	vGT_name = "AS" + value.ASN_PName.String() + "_GT_Patch"
// 	vGT      *template.Template
// 	vBuf     bytes.Buffer
// )
// switch vGT, err = template.New(vGT_name).Funcs(gt_fm).Parse(value.GT_Patch.String()); err == nil && vGT != nil {
// // switch vGT, err = template.New("config.tmpl").Funcs(gt_fm).ParseFiles("config.tmpl"); err == nil && vGT != nil {
// case true:
// 	switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
// 	case true:
// 		config[index] = append(config[index], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
// 	default:
// 		log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
// 		continue
// 	}
// default:
// 	log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
// 	continue
// }
// }

// tabber(pdb_peer[index].Manufacturer, 2) + "\t"+
// tabber(pdb_peer[index].Model, 2) + "\t####\t\t" +

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

/*
set policy-options prefix-list AS{{.VI_INSIDE_RIGHT_AS}} {{.VI_INSIDE_LEFT_SUBNET}}
set policy-options policy-statement pass_AS{{.VI_INSIDE_RIGHT_AS}} term ACCEPT from prefix-list-filter AS{{.VI_INSIDE_RIGHT_AS}} orlonger
set policy-options policy-statement pass_AS{{.VI_INSIDE_RIGHT_AS}} term ACCEPT then next policy
set policy-options policy-statement pass_AS{{.VI_INSIDE_RIGHT_AS}} term REJECT then reject
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} description {{.VI_OUTSIDE_LEFT_RI}}-{{.VI_OUTSIDE_RIGHT_RI}}-{{.VI_OUTSIDE_RIGHT_IF}}
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} local-address {{.VI_INSIDE_LEFT_IP}}
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} import filter_DE
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} import pass_AS{{.VI_INSIDE_RIGHT_AS}}
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} import import_1Mb
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} export aggregate
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} export aggregate_intranet
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} export filter_DE
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} export export_1Mb
set protocols bgp group AS4200000000 neighbor {{.VI_INSIDE_RIGHT_IP}} peer-as {{.VI_INSIDE_RIGHT_AS}}
*/

const (
	_juniper_RI_              _Name          = "master"
	_juniper_mgmt_RI          _Name          = "mgmt_junos"
	_juniper_mgmt_Description _Description   = "MANAGEMENT-INSTANCE"
	_if_comm_ptp              _Communication = "ptp"
	_if_comm_ptmp             _Communication = "ptmp"
	_vi_comm_                                = _if_comm_ptp
	_if_comm_                                = _if_comm_ptmp
	_if_mode_vi               _Mode          = "vi"
	_if_mode_link             _Mode          = "link"
	_service_ike              _Service       = "ike"
	_service_ping             _Service       = "ping"
	_service_ssh              _Service       = "ssh"
	_service_traceroute       _Service       = "traceroute"
	_protocol_bgp             _Protocol      = "bgp"
	_AB_Type_set              _Type          = "set"
	_AB_Type_ipprefix         _Type          = "ipprefix"
	_AB_Type_fqdn             _Type          = "fqdn"
)

var (
// _loglevel = default_loglevel
)

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
			v_SZ = make(map[_Name]pDB_Peer_Security_Zone_SZ)
		)
		for _, b := range value.SZ {
			_SZ_create(&v_SZ, "", b)
		}

		var (
			v_IP_List   = make(map[netip.Prefix]bool)
			v_ASN_PName = value.ASN._PName()
			v_Hostname  = func() (outbound _FQDN) {
				switch len(value.Hostname) == 0 {
				case true:
					outbound = _FQDN("gw_as" + v_ASN_PName.String())
					log.Warnf("peer ASN '%v' hostname not defined; ACTION: use '%v'.", value.ASN, outbound)
					return
				}
				return value.Hostname
			}()
			v_GT_List = func() (outbound []_Name) {
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
					switch _, flag := pdb_gt[_Name(list_v)]; flag {
					case true:
						switch pdb_gt[_Name(list_v)].Reserved {
						case false:
							outbound = append(outbound, _Name(list_v))
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
			v_IF_RI     = make(map[_Name]_Name)
			v_RI        = func() (outbound map[_Name]pDB_Peer_RI) {
				var (
					vIP_IF = make(map[netip.Addr]_Name)
				)
				outbound = make(map[_Name]pDB_Peer_RI)
				for _, ri_v := range value.RI {
					switch ri_v.Name == _juniper_mgmt_RI {
					case false:
						_SZ_create(&v_SZ, ri_v.Name, pDB_Peer_Security_Zone_SZ{})
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
									GW: func() (gw_o map[_Name]pDB_Peer_RI_RT_GW) {
										gw_o = make(map[_Name]pDB_Peer_RI_RT_GW)
										for _, gw_v := range rt_v.GW {
											var (
												gw_i  = strconv.FormatUint(uint64(gw_v.Metric), 10) + "_"
												gw_IF _Name
												gw_IP netip.Addr
												gw_T  _Name
											)
											switch {
											case gw_v.Action == _Action_discard:
												gw_i += _Action_discard.String()
												gw_v.Action = c_Action[gw_v.Action]
											case (gw_v.Action == _Action_qnh || gw_v.Action == _Action_hop) && gw_v.IP.IsValid():
												gw_i += gw_v.IP.String()
												gw_IP = gw_v.IP
												gw_v.Action = c_Action[gw_v.Action]
											case (gw_v.Action == _Action_qnh || gw_v.Action == _Action_hop || gw_v.Action == _Action_interface) && len(gw_v.IF) != 0:
												gw_i += gw_v.IF.String()
												gw_IF = gw_v.IF
												gw_v.Action = c_Action[gw_v.Action]
											case gw_v.Action == _Action_hop && gw_v.IP.IsValid():
												gw_i += gw_v.IP.String()
												gw_IP = gw_v.IP
												gw_v.Action = c_Action[gw_v.Action]
											case gw_v.Action == _Action_interface && len(gw_v.IF) != 0:
												gw_i += gw_v.IF.String()
												gw_IF = gw_v.IF
												gw_v.Action = c_Action[gw_v.Action]
											case gw_v.Action == _Action_table && len(gw_v.Table) != 0:
												gw_i += gw_v.Table.String()
												gw_T = gw_v.Table
												gw_v.Action = c_Action[gw_v.Action]
											case len(gw_v.Action) == 0 && gw_v.IP.IsValid():
												gw_i += gw_v.IP.String()
												gw_IP = gw_v.IP
												gw_v.Action = c_Action[_Action_hop]
											case len(gw_v.Action) == 0 && len(gw_v.IF) != 0:
												gw_i += gw_v.IF.String()
												gw_IF = gw_v.IF
												gw_v.Action = c_Action[_Action_interface]
											case len(gw_v.Action) == 0 && len(gw_v.Table) != 0:
												gw_i += gw_v.Table.String()
												gw_T = gw_v.Table
												gw_v.Action = c_Action[_Action_table]
											default:
												log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', no gateway found or unknown gateway action '%v'; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier, gw_v.Action)
												gw_i += _Action_discard.String()
												continue
											}
											switch _, flag := gw_o[_Name(gw_i)]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', gateway '%v' already defined; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier, gw_i)
												continue
											}
											gw_o[_Name(gw_i)] = pDB_Peer_RI_RT_GW{
												IP:                  gw_IP,
												IF:                  gw_IF,
												Table:               gw_T,
												Action:              gw_v.Action,
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
						IF: func() (if_o map[_Name]pDB_Peer_RI_IF) {
							if_o = make(map[_Name]pDB_Peer_RI_IF)
							for _, if_v := range ri_v.IF {
								switch if_ri_v, flag := v_IF_RI[if_v.Name]; flag {
								case true:
									log.Warnf("peer ASN '%v', RI '%v', IF '%v' already defined in RI '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, if_ri_v)
									continue
								}
								v_IF_RI[if_v.Name] = ri_v.Name
								var (
									IF_split  = re_dot.Split(if_v.Name.String(), -1)
									if_o_IFM  = _Name(IF_split[0])
									if_o_IFsM = _Name(IF_split[1])
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
									v_SZ[ri_v.Name].IF[if_v.Name] = pDB_Peer_Security_Zone_SZ_IF{
										_Host_Inbound_Traffic: _Host_Inbound_Traffic{
											Services: map[_Service]bool{
												_service_ping:       true,
												_service_ssh:        true,
												_service_traceroute: true,
											},
											Protocols: map[_Protocol]bool{},
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
			v_IFM = func() (outbound map[_Name]pDB_Peer_IFM) {
				outbound = make(map[_Name]pDB_Peer_IFM)
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
					return _Defaults[_domain_name].(_FQDN)
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
			ASN:         value.ASN,
			ASN_PName:   v_ASN_PName,
			Router_ID:   v_Router_ID,
			AB:          map[_Name]_Security_AB{},
			Application: map[_Name][]_Security_Application_Term{},
			SZ:          v_SZ,
			_Security_NAT_List: _Security_NAT_List{
				Source:      value.NAT.Source,
				Destination: value.NAT.Destination,
				Static:      value.NAT.Static,
			},
			_Security_SP: _Security_SP{
				SP_Default: value.SP.SP_Default._SP_Validate(),
				SP_Exact: func() (outbound []_Security_Rule_Set) {
					for _, b := range value.SP.SP_Exact {
						for _, d := range b.To {
							for _, f := range b.From {
								outbound = append(outbound, _Security_Rule_Set{
									From:                []_Security_Direction{f},
									To:                  []_Security_Direction{d},
									Rule:                b.Rule,
									_Service_Attributes: b._Service_Attributes,
								})
							}
						}
					}
					return
				}(),
				SP_Global: value.SP.SP_Global,
			},
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
			IPPrefix_List:       v_IP_List,
			_Service_Attributes: value._Service_Attributes,
		}

		b := pdb_peer[value.ASN]
		b = b
	}
	for _, value := range pdb_peer {
		var (
			_v_AB_list          = make(map[_Name]bool)
			_v_Application_list = make(map[_Name]bool)
		)
		for _, b := range value.Source {
			for _, d := range b.Rule_Set {
				for _, x := range d.Rule {
					for _, z := range x.Match {
						switch len(z.Source_AB) == 0 {
						case false:
							_v_AB_list[z.Source_AB] = true
						}
						switch len(z.Destination_AB) == 0 {
						case false:
							_v_AB_list[z.Destination_AB] = true
						}
						switch len(z.Application) == 0 {
						case false:
							_v_Application_list[z.Application] = true
						}
					}
				}
			}
		}
		for _, b := range value.Destination {
			for _, d := range b.Rule_Set {
				for _, x := range d.Rule {
					for _, z := range x.Match {
						switch len(z.Source_AB) == 0 {
						case false:
							_v_AB_list[z.Source_AB] = true
						}
						switch len(z.Destination_AB) == 0 {
						case false:
							_v_AB_list[z.Destination_AB] = true
						}
						switch len(z.Application) == 0 {
						case false:
							_v_Application_list[z.Application] = true
						}
					}
				}
			}
		}
		for _, b := range value.SP_Exact {
			for _, x := range b.Rule {
				for _, z := range x.Match {
					switch len(z.Source_AB) == 0 {
					case false:
						_v_AB_list[z.Source_AB] = true
					}
					switch len(z.Destination_AB) == 0 {
					case false:
						_v_AB_list[z.Destination_AB] = true
					}
					switch len(z.Application) == 0 {
					case false:
						_v_Application_list[z.Application] = true
					}
				}
			}
		}
		for _, x := range value.SP_Global {
			for _, z := range x.Match {
				switch len(z.Source_AB) == 0 {
				case false:
					_v_AB_list[z.Source_AB] = true
				}
				switch len(z.Destination_AB) == 0 {
				case false:
					_v_AB_list[z.Destination_AB] = true
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
				v_Type   = value.Type._VI_Sanitize()
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
				value.Peer[peer_index].RI = value.Peer[peer_index].RI._Validate(_juniper_mgmt_RI)
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI]; flag {
				case false:
					log.Warnf("VI '%v', ASN '%v', RI '%v' not defined; ACTION: skip.", value.ID, value.Peer[peer_index].ASN, value.Peer[peer_index].RI)
					return
				}
				value.Peer[peer_index].Inner_RI = value.Peer[peer_index].Inner_RI._Validate(_juniper_mgmt_RI)
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
				pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].Services[_service_ike] = true
				pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].Inner_RI].IF[_Name(v_Type.String()+"0."+value.ID.String())] = pDB_Peer_Security_Zone_SZ_IF{
					_Host_Inbound_Traffic: _Host_Inbound_Traffic{
						Services: map[_Service]bool{
							_service_ping:       true,
							_service_ssh:        true,
							_service_traceroute: true,
						},
						Protocols: map[_Protocol]bool{
							_protocol_bgp: true,
						},
					},
					_Service_Attributes: _Service_Attributes{},
				}
				// pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].Inner_RI].IF[_Name(v_Type.String()+"0."+value.ID.String())]._Defaults()
				pdb_peer[value.Peer[peer_index].ASN].SZ[value.Peer[peer_index].Inner_RI].IF[_Name(v_Type.String()+"0."+value.ID.String())].Protocols[_protocol_bgp] = true
			}
			var (
				v_Metric = func() uint32 {
					switch value.Route_Metric > _Defaults[_ps_max_rms].(uint32) {
					case true:
						return 0
					}
					return _Defaults[_ps_max_rms].(uint32) - value.Route_Metric
				}()
				v_Left_Inner_IPPrefix  = get_VI_IPPrefix(value.ID, 1)
				v_Right_Inner_IPPrefix = get_VI_IPPrefix(value.ID, 2)
			)
			pdb_peer[value.Peer[0].ASN].VI[value.ID] = pDB_Peer_VI{
				VI_ID_PName:          value.ID._PName(),
				Type:                 v_Type,
				Communication:        value.Communication._Sanitize(_if_mode_vi),
				PSK:                  value.PSK._Sanitize(64),
				Route_Metric:         v_Metric,
				IPPrefix:             get_VI_IPPrefix(value.ID, 0),
				No_NAT:               v_No_NAT,
				IKE_GCM:              pdb_peer[value.Peer[0].ASN].IKE_GCM && pdb_peer[value.Peer[1].ASN].IKE_GCM,
				Left_ASN:             value.Peer[0].ASN,
				Left_RI:              value.Peer[0].RI,
				Left_IF:              value.Peer[0].IF,
				Left_IP:              value.Peer[0].IP,
				Left_NAT:             v_NAT[0],
				Left_Local_Address:   len(pdb_peer[value.Peer[0].ASN].RI[value.Peer[0].RI].IF[value.Peer[0].IF].IP) > 1,
				Left_Dynamic:         value.Peer[0].Dynamic,
				Left_Inner_RI:        value.Peer[0].Inner_RI._Validate(_juniper_mgmt_RI),
				Left_Inner_IP:        v_Left_Inner_IPPrefix.Addr(),
				Left_Inner_IPPrefix:  v_Left_Inner_IPPrefix,
				Right_ASN:            value.Peer[1].ASN,
				Right_RI:             value.Peer[1].RI,
				Right_IF:             value.Peer[1].IF,
				Right_IP:             value.Peer[1].IP,
				Right_NAT:            v_NAT[1],
				Right_Local_Address:  len(pdb_peer[value.Peer[1].ASN].RI[value.Peer[1].RI].IF[value.Peer[1].IF].IP) > 1,
				Right_Dynamic:        value.Peer[1].Dynamic,
				Right_Inner_RI:       value.Peer[1].Inner_RI._Validate(_juniper_mgmt_RI),
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
						vGT  *template.Template
						vBuf bytes.Buffer
					)
					switch vGT, err = template.New(gt_v.String()).Funcs(gt_fm).Parse(pdb_gt[gt_v].Content.String()); err == nil && vGT != nil {
					case true:
						switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
						case true:
							config[index] = append(config[index], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
						default:
							log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), gt_v, err)
							return
						}
					default:
						log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), gt_v, err)
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
			fn = _Defaults[_path_out].(string) + "./AS" + index.String()
		)
		switch err_i := os.WriteFile(fn, value, 0600); err_i == nil {
		case true:
			log.Debugf("OK '%v'", index)
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

	switch err_i := os.WriteFile(_Defaults[_path_out].(string)+"./hosts.txt", []byte(hosts), 0600); err_i == nil {
	case true:
		log.Infof("OK 'hosts.txt'")
	case false:
		log.Errorf("Fail 'hosts.txt' with error '%v'", err_i)
	}

	log.Debugf("\n%s\n", hosts)
	return
}

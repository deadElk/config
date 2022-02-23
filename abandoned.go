package main

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

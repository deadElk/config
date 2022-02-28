package main

func parse_iDB_Peer() (ok bool) {
	for a := range i_peer {
		for c := range i_peer[a].RI {
			switch _, flag := i_ps["redistribute_"+c]; flag {
			case false:
				i_ps["redistribute_"+c] = i_PO_PS{
					Term: []i_PO_PS_Term{
						0: {
							Name: "PERMIT",
							From: []i_PO_PS_From{
								0: {RI: c, _Service_Attributes: _Service_Attributes{}},
							},
							Then: []i_PO_PS_Then{
								0: {Action: _Action_accept, _Service_Attributes: _Service_Attributes{}},
							},
							_Service_Attributes: _Service_Attributes{},
						},
					},
					_Service_Attributes: _Service_Attributes{},
				}
			}
			switch c == _Defaults[_mgmt_RI].(_Name) {
			case false:
				switch _, flag := i_peer[a].SZ[c]; flag {
				case false:
					i_peer[a].SZ[c] = i_SZ{
						Screen:                "",
						IF:                    map[_Name]_Host_Inbound_Traffic{},
						_Host_Inbound_Traffic: parse_Host_Inbound_Traffic(),
						_Service_Attributes:   _Service_Attributes{},
					}
				}
				for e := range i_peer[a].RI[c].IF {
					switch _, flag := i_peer[a].SZ[c].IF[e]; flag {
					case false:
						i_peer[a].SZ[c].IF[e] = parse_Host_Inbound_Traffic(_Service_ping, _Service_traceroute, _Service_ssh)
					}
				}
			}
			// i_peer[a].RI[c].Leak[_Action_import] = i_Peer_RI_RO_Leak_FromTo{
			// 	PL: func() (outbound []_Name) {
			// 		for _, f := range b.From {
			// 			switch _, flag = i_ps[f.PL]; flag {
			// 			case false:
			// 				log.Warnf("Peer '%v', RI '%v', configured Policy List '%v' not found; ACTION: ignore.", a, c, f.PL)
			// 				continue
			// 			}
			// 			outbound = append(outbound, f.PL)
			// 		}
			// 		return
			// 	}(),
			// }
			// i_peer[a].RI[c].Leak[_Action_export] = i_Peer_RI_RO_Leak_FromTo{
			// 	PL: func() (outbound []_Name) {
			// 		for _, f := range b.To {
			// 			switch _, flag = i_ps[f.PL]; flag {
			// 			case false:
			// 				log.Warnf("Peer '%v', RI '%v', configured Policy List '%v' not found; ACTION: ignore.", a, c, f.PL)
			// 				continue
			// 			}
			// 			outbound = append(outbound, f.PL)
			// 		}
			// 		return
			// 	}(),
			// }

		}
	}
	return true
}

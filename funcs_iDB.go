package main

func parse_iDB_Peer() (ok bool) {
	// for a := range i_peer {
	// for c := range i_peer[a].RI {
	// }
	// }
	return true
}

func parse_iDB_VI_Peer() (ok bool) {
	for a, b := range i_vi_peer {
		var (
			i = make(map[_VI_Peer_ID]_ASN)
		)
		for c, d := range b {
			i[c] = d.ASN
			m := &i_vi_peer[a]
			// i_peer[i[c]].VI = map[_VI_ID]*i_VI{
			// 	PName:               "",
			// 	IPPrefix:            netip.Prefix{},
			// 	IKE_No_NAT:          false,
			// 	IKE_GCM:             false,
			// 	Type:                "",
			// 	Communication:       "",
			// 	Route_Metric:        0,
			// 	PSK:                 "",
			// 	_Service_Attributes: _Service_Attributes{},
			// }
		}
	}
	return true
}

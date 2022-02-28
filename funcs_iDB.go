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
			i1 _VI_Peer_ID = 0
			i2 _VI_Peer_ID = 1
			p1             = b[i1].ASN
			p2             = b[i2].ASN
		)
	}
	return true
}

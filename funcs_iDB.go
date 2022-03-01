package main

func parse_iDB() (ok bool) {
	parse_iDB_Peer_Vocabulary()
	return true
}

func parse_iDB_Peer_Vocabulary() (ok bool) {
	for y, v_Peer := range i_peer {

		var (
			interim = make(map[_Name]*i_AB)
		)
		for a := range v_Peer.AB {
			peer_iDB_recurse_AB(&interim, a)
		}
		v_Peer.AB = interim

		for _, b := range v_Peer.PS {
			for _, d := range b.Term {
				for _, f := range d.From {
					v_Peer.link_PL(f.PL)
				}
			}
		}

		i_peer[y] = v_Peer
	}
	return
}
func peer_iDB_recurse_AB(interim *map[_Name]*i_AB, inbound _Name) (ok bool) {
	(*interim)[inbound] = i_ab[inbound]
	for a, b := range i_ab[inbound].Address_Set {
		switch {
		case b != _Type_set:
			peer_iDB_recurse_AB(interim, a)
		case (*interim)[a] == nil:
			peer_iDB_recurse_AB(interim, a)
		}
	}
	return
}

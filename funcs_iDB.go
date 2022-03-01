package main

// func parse_iDB_Peer_Vocabulary() (ok bool) {
// 	// for _, value := range i_peer {
// 	// 	var (
// 	// 		v_ab_list = make(map[_Name]bool)
// 	// 		v_ja_list = make(map[_Name]bool)
// 	// 		v_pl_list = make(map[_Name]bool)
// 	// 		v_ps_list = make(map[_Name]bool)
// 	// 	)
// 	// 	for _, b := range value.RI {
// 	// 		for _, d := range b.Leak {
// 	// 			for _, f := range d.PL {
// 	// 				v_pl_list[f] = true
// 	// 			}
// 	// 		}
// 	// 	}
// 	// 	for _, b := range value.NAT {
// 	// 		for _, d := range b.Rule_Set {
// 	// 			for _, f := range d.From {
// 	// 				v_ab_list[f.AB] = true
// 	// 			}
// 	// 			for _, f := range d.To {
// 	// 				v_ab_list[f.AB] = true
// 	// 			}
// 	// 			for _, f := range d.Rule {
// 	// 				for _, h := range f.JA {
// 	// 					v_ja_list[h] = true
// 	// 				}
// 	// 				for _, h := range f.From {
// 	// 					v_ja_list[h] = true
// 	// 				}
// 	// 			}
// 	// 		}
// 	// 	}
// 	//
// 	// 	v_ab_list = _AB_rparse(v_ab_list)
// 	//
// 	// 	for a := range v_ab_list {
// 	// 		value.AB[a] = pdb_ab[a]
// 	// 	}
// 	// 	for a := range v_ja_list {
// 	// 		value.Application[a] = pdb_appl[a]
// 	// 	}
// 	// }
// 	// return true
// }

func peer_iDB_Vocabulary() (ok bool) {
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

// func peer_iDB_parse_AB(_v_AB_list map[_Name]bool) (outbound map[_Name]bool) {
// 	outbound = make(map[_Name]bool)
// 	for a := range _v_AB_list {
// 		switch {
// 		case i_ab[a].Type != _Type_set:
// 			outbound[a] = true
// 		default:
// 			peer_iDB_recurse_AB(&outbound, a)
// 		}
// 	}
// 	return
// }
// func peer_iDB_recurse_AB(_v_AB_list *map[_Name]bool, a _Name) (ok bool) {
// 	(*_v_AB_list)[a] = true
// 	for c, d := range i_ab[a].Address_Set {
// 		switch {
// 		case d != _Type_set:
// 			(*_v_AB_list)[c] = true
// 		case !(*_v_AB_list)[c]:
// 			peer_iDB_recurse_AB(_v_AB_list, c)
// 		}
// 	}
// 	return
// }

package main

import (
	log "github.com/sirupsen/logrus"
)

func parse_iDB() (ok bool) {
	// define_iDB_PS()
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
	return true
}
func peer_iDB_recurse_AB(interim *map[_Name]*i_AB, inbound _Name) (ok bool) {
	(*interim)[inbound] = i_ab[inbound]
	for a, b := range i_ab[inbound].Set {
		switch {
		case b.Type != _Type_set || (*interim)[a] == nil:
			peer_iDB_recurse_AB(interim, a)
		}
	}
	return true
}

func define_iDB_PS() (ok bool) {
	for a, b := uint32(0), _Route_Weight(1); a <= uint32(_Route_Weight_max_rm); a, b = a+1, b<<int(_Route_Weight_bits_per_rm) {
		var (
			c = _Name(strings_join("_", _Action_import_metric, pad(a, 2)))
			d = _Name(strings_join("_", _Action_export_metric, pad(a, 2)))
		)
		switch {
		case i_ps[c] != nil:
			log.Debugf("Policy Statement '%v' already exist; ACTION: skip.", c)
			continue
		case i_ps[d] != nil:
			log.Debugf("Policy Statement '%v' already exist; ACTION: skip.", d)
			continue
		}

		i_ps[c] = &i_PO_PS{
			Term: []i_PO_PS_Term{
				0: {
					Name: "ACCEPT",
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Action_Flag: _Action_add, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, _Action_add, b)},
						1: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "ACCEPT"),
				},
			},
			GT_Action: strings_join(" ", _Action_policy__options___policy__statement, c),
		}

		i_ps[d] = &i_PO_PS{
			Term: []i_PO_PS_Term{
				0: {
					Name: "LOCAL",
					From: []i_PO_PS_From{
						0: {Protocol: _Protocol_access_internal, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_access_internal)},
						1: {Protocol: _Protocol_local, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_local)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_reject, GT_Action: strings_join(" ", _Action_then, _Action_reject)},
					},
					GT_Action: strings_join(" ", _Action_term, "LOCAL"),
				},

				1: {
					Name: "DIRECT",
					From: []i_PO_PS_From{
						0: {Protocol: _Protocol_direct, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_direct)},
						1: {Protocol: _Protocol_static, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_static)},
						2: {Protocol: _Protocol_aggregate, GT_Action: strings_join(" ", _Action_from, _Action_protocol, _Protocol_aggregate)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, b)},
						1: {Action: _Action_next__hop, Action_Flag: _Action_self, GT_Action: strings_join(" ", _Action_then, _Action_next__hop, _Action_self)},
						2: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "DIRECT"),
				},
				2: {
					Name: "INTERNAL",
					From: []i_PO_PS_From{
						0: {Route_Type: _Type_internal, GT_Action: strings_join(" ", _Action_from, _Action_route__type, _Type_internal)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Action_Flag: _Action_add, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, _Action_add, b+1)},
						1: {Action: _Action_next__hop, Action_Flag: _Action_self, GT_Action: strings_join(" ", _Action_then, _Action_next__hop, _Action_self)},
						2: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "INTERNAL"),
				},
				3: {
					Name: "EXTERNAL",
					From: []i_PO_PS_From{
						0: {Route_Type: _Type_external, GT_Action: strings_join(" ", _Action_from, _Action_route__type, _Type_external)},
					},
					Then: []i_PO_PS_Then{
						0: {Action: _Action_metric, Action_Flag: _Action_add, Metric: b, GT_Action: strings_join(" ", _Action_then, _Action_metric, _Action_add, b)},
						1: {Action: _Action_next__hop, Action_Flag: _Action_self, GT_Action: strings_join(" ", _Action_then, _Action_next__hop, _Action_self)},
						2: {Action: _Action_accept, GT_Action: strings_join(" ", _Action_then, _Action_accept)},
					},
					GT_Action: strings_join(" ", _Action_term, "EXTERNAL"),
				},

				4: {
					Name: "REJECT",
					Then: []i_PO_PS_Then{
						0: {Action: _Action_reject, GT_Action: strings_join(" ", _Action_then, _Action_reject)},
					},
					GT_Action: strings_join(" ", _Action_term, "REJECT"),
				},
			},
			GT_Action: strings_join(" ", _Action_policy__options___policy__statement, d),
		}

	}
	return true
}

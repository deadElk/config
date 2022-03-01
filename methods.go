package main

import (
	"crypto/rand"
	"math/big"

	log "github.com/sirupsen/logrus"
)

func (inbound *_Secret) validate(length uint, message ...string) _Secret {
	switch len(*inbound) >= int(length) {
	case true:
		return *inbound
	}
	var (
		interim = make([]byte, length)
	)
	for i := 0; i < int(length); i++ {
		switch next, err := rand.Int(rand.Reader, big.NewInt(int64(len(_passwd)))); err == nil && next != nil {
		case true:
			interim[i] = _passwd[next.Int64()]
		default:
			log.Panicf("rand.Int error: %#v", err)
		}
	}
	switch len(message) > 0 {
	case true:
		log.Warnf("%v; ACTION: new value is '%v'.", message[0], string(interim))
	}
	return _Secret(interim)
}
func (inbound *_Name) validate_RI(decline ..._Name) (outbound _Name) {
	outbound = _Defaults[_RI].(_Name)
	switch len(*inbound) == 0 || *inbound == outbound {
	case true:
		return
	}
	for _, interim := range decline {
		switch *inbound == interim {
		case true:
			return
		}
	}
	return *inbound
}

func (inbound *i_Peer) link_AB(name ..._Name) {
	for _, value := range name {
		switch i_ab[value] == nil {
		case true:
			continue
		}
		inbound.AB[value] = i_ab[value]
	}
}
func (inbound *i_Peer) link_JA(name ..._Name) {
	for _, value := range name {
		switch i_ja[value] == nil {
		case true:
			continue
		}
		inbound.JA[value] = i_ja[value]
	}
}
func (inbound *i_Peer) link_PL(name ..._Name) {
	for _, value := range name {
		switch i_pl[value] == nil {
		case true:
			continue
		}
		inbound.PL[value] = i_pl[value]
	}
}
func (inbound *i_Peer) link_PS(name ..._Name) {
	for _, value := range name {
		switch i_ps[value] == nil {
		case true:
			continue
		}
		inbound.PS[value] = i_ps[value]
	}
}

func (inbound *i_AB) make_gt_action(content ...i_AB) {
	// for _, _ := range content {
	//
	// }
}

// {{range $a, $b := .AB -}}
//    {{if eq $b.Type "set" -}}
//        {{range $c, $d := $b.Address_Set -}}
//            {{if eq $d "set" -}}
//							set security address-book global address-set {{$a}} address-set {{$c}}
//            {{else if or (eq $d "fqdn") (eq $d "ipprefix") -}}
//							set security address-book global address-set {{$a}} address {{$c}}
//            {{end -}}
//        {{end -}}
//    {{else if eq $b.Type "fqdn" -}}
//			set security address-book global address {{$a}} dns-name {{$b.Address}}
//    {{else if eq $b.Type "ipprefix" -}}
//			set security address-book global address {{$a}} address {{$b.Address}}
//    {{end -}}
// {{end -}}

func (inbound *i_JA) make_gt_action(content ...i_JA)       {}
func (inbound *i_PO_PL) make_gt_action(content ...i_PO_PL) {}
func (inbound *i_PO_PS) make_gt_action(content ...i_PO_PS) {}

// 		switch _, flag := i_ps["redistribute_"+b.Name]; {
//		case !flag:
//			i_ps["redistribute_"+b.Name] = &i_PO_PS{
//				Term: []i_PO_PS_Term{
//					0: {
//						Name: "PERMIT",
//						From: []i_PO_PS_From{0: {
//							RI:         b.Name,
//							Protocol:   "",
//							Route_Type: "",
//							PL:         "",
//							Mask:       "",
//							_GT_Action: _GT_Action{
//								GT_Action: "from routing-instance " + b.Name.String(),
//							},
//							_Service_Attributes: _Service_Attributes{},
//						}},
//						Then: []i_PO_PS_Then{0: {
//							Action:      _Action_accept,
//							Action_Flag: "",
//							Metric:      0,
//							_GT_Action: _GT_Action{
//								GT_Action: "then "+ _Action_accept.String(),
//							},
//							_Service_Attributes: _Service_Attributes{},
//						}},
//						_GT_Action: _GT_Action{
//							GT_Action: "",
//						},
//						_Service_Attributes: _Service_Attributes{},
//					},
//				},
//				_GT_Action: _GT_Action{
//					GT_Action: "term PERMIT",
//				},
//				_Service_Attributes: _Service_Attributes{},
//			}
//			v_Peer.link_PS("redistribute_" + b.Name)
//		}
//	}

//		_GT_Action: _GT_Action{
//			GT_Action: "set security address-book global",
//		},

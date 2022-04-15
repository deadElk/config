package main

import (
	log "github.com/sirupsen/logrus"
)

func (receiver *i_Peer) link_AB(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ab[value] == nil:
			continue
		}
		receiver.AB[value] = i_ab[value]
	}
}
func (receiver *i_Peer) link_JA(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ja[value] == nil:
			continue
		}
		receiver.JA[value] = i_ja[value]
	}
}
func (receiver *i_Peer) link_PL(name ..._Name) {
	for _, value := range name {
		switch {
		case i_pl[value] == nil:
			continue
		}
		receiver.PL[value] = i_pl[value]
	}
}
func (receiver *i_Peer) link_PS(name ..._Name) {
	for _, value := range name {
		switch {
		case i_ps[value] == nil:
			continue
		}
		receiver.PS[value] = i_ps[value]
	}
}
func (receiver *i_Peer) create_AB_Set(name ..._Name) {
	for _, value := range name {
		create_iDB_AB_Set(value)
		receiver.link_AB(value)
	}
}

func (receiver *i_AB) get_address_list(interim *[]_Name) (outbound *[]_Name) {
	switch receiver.Type {
	case _Type_fqdn:
		return &[]_Name{0: _Name(receiver.FQDN)}
	case _Type_ipprefix:
		return &[]_Name{0: _Name(receiver.IPPrefix.String())}
	case _Type_set:
		var (
			t []_Name
		)
		for b := range receiver.Set {
			var (
				i = i_ab[b].get_address_list(interim)
			)
			for _, d := range *i {
				t = append(t, d)
			}
		}
		return &t
	}
	return
}
func (receiver __N_AB) parse_recurse_AB(inbound _Name) {
	receiver[inbound] = i_ab[inbound]
	for a, b := range i_ab[inbound].Set {
		switch {
		case b.Type != _Type_set || receiver[a] == nil:
			receiver.parse_recurse_AB(a)
		}
	}
}

func (receiver __ASN_Peer) parse_GT() (status bool) {
	for index, value := range receiver {
		switch {
		case value.Reserved:
			continue
		}
		i_file.put(_dir_Config, _File_Name(value.ASName).a("txt"), "\n", "")
		for _, gt_v := range value.GT_List {
			var (
				content = i_file.get(_dir_GT, _File_Name(gt_v).a("tmpl")).parse_GT(value)
			)
			switch {
			case content == nil:
				log.Warnf("peer '%v', template '%v' parser returned nil; ACTION: ignore.", index.String(), gt_v)
				status = true
				continue
			}
			i_file.append(_dir_Config, _File_Name(value.ASName).a("txt"), "\n", content)
		}
	}
	return !status
}

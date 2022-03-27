package main

import (
	"bytes"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func (receiver *i_LDAP_Domain) replace(attrName string, attrVals []string) {
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	// switch attrName {
	// case _skv_CA, _skv_acrl, _skv_CRL:
	// 	// attrName += ";binary" // todo: VERY BAD IDEA!
	// }

	receiver.Modify.Replace(attrName, attrVals)
}
func (receiver *i_LDAP_Domain_User) replace(attrName string, attrVals []string) {
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}
func (receiver *i_LDAP_Domain_Group) replace(attrName string, attrVals []string) {
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}

func (receiver *i_LDAP) _DN_FQDN(inbound _DN) (outbound _FQDN) {
	var (
		interim  = re_commas.Split(inbound.String(), -1)
		inbounds = len(interim) - 1
		buffer   = new(bytes.Buffer)
	)
	for a, b := range interim {
		switch {
		case len(b) == 0:
			log.Warnf("malformed DN '%v'; ACTION: ignore", inbound)
			continue
		}
		var (
			delimiter string
			d         = re_equals.Split(b, -1)
		)
		switch {
		case len(d) != 2:
			log.Warnf("malformed DN '%v'; ACTION: ignore", inbound)
			continue
		}
		switch d[0] {
		case _W_dc.String(): // todo: is this dirty?
			delimiter = _re_point
		case receiver.Group_CN:
			delimiter = _re_point
		case receiver.User_CN:
			delimiter = _re_dog
		default:
			continue
		}

		buffer.WriteString(d[1])
		switch {
		case a < inbounds:
			buffer.WriteString(delimiter)
		}
	}
	return _FQDN(buffer.String())
}

func /*(receiver bool) */ parse_SKV() (status bool) {
	return
}
func (receiver slstrings) get_first() (outbound string) {
	for _, b := range receiver {
		return b
	}
	return
}
func (receiver slstrings) get_map() (outbound map[string]string) {
	outbound = make(map[string]string)
	for _, b := range receiver {
		outbound[b] = ""
	}
	return
}

func (receiver *i_LDAP_Domain_Group) parse_VPN_SKV() (status bool) {
	receiver.VPN_SKV = make(_SKV)
	for _, b := range receiver.SKV[_skv_labeledURI] {
		var (
			c = re_string_splitters.Split(b, -1)
			d = len(c)
		)
		switch {
		case d >= 2:
			receiver.VPN_SKV[c[0]] = func() (outbound slstrings) {
				for e := 1; e <= d-1; e++ {
					outbound = append(outbound, c[e])
				}
				return
			}()
		}
	}
	receiver.VPN = &i_LDAP_VPN{
		outside_IPPrefix: receiver.VPN_SKV["openvpn"].get_map(),
		ssp:              parse_interface(strconv.ParseBool(receiver.VPN_SKV["openvpn_ssp"].get_first())).(bool),
		port:             _INet_Port(string_uint64(receiver.VPN_SKV["openvpnd_port"].get_first())),
		firewall_v00:     receiver.VPN_SKV["firewall_v00"].get_map(),
	}
	return
}

package main

import (
	"bytes"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func (receiver *i_LDAP_Domain) modify(attrName string, attrVals []string) {
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), []ldap.Control{})
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}
func (receiver *i_LDAP_Domain_User) modify(attrName string, attrVals []string) {
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}
func (receiver *i_LDAP_Domain_Group) modify(attrName string, attrVals []string) {
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

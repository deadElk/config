package main

import (
	"bytes"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

func (receiver *i_LDAP_Domain) replace(attrName string, attrVals []string) {
	switch {
	case len(attrVals) == 0 || len(attrName) == 0:
		return
	}
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
	case len(attrVals) == 0 || len(attrName) == 0:
		return
	}
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}
func (receiver *i_LDAP_Domain_Group) replace(attrName string, attrVals []string) {
	switch {
	case len(attrVals) == 0 || len(attrName) == 0:
		return
	}
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}
func (receiver *i_LDAP_Domain_Host) replace(attrName string, attrVals []string) {
	switch {
	case len(attrVals) == 0 || len(attrName) == 0:
		return
	}
	switch {
	case receiver.Modify == nil:
		receiver.Modify = ldap.NewModifyRequest(receiver.DN.String(), nil)
	}
	ldap_modify_Add_Attr(receiver.Entry, receiver.Modify, attrName)
	receiver.Modify.Replace(attrName, attrVals)
}

func (receiver *i_LDAP) _DN_FQDN(style string, inbound _DN) (outbound _FQDN) {
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
		case receiver.Host_CN, receiver.Group_CN, receiver.User_CN:
			delimiter = style
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

func (receiver *i_LDAP_SKV) get_first() (outbound string) {
	switch {
	case receiver != nil && len(receiver.Ordered) > 0:
		return receiver.Ordered[0]
	}
	return
}
func (receiver *i_LDAP_SKV) get_all() (outbound []string) {
	switch {
	case receiver != nil && len(receiver.Ordered) > 0:
		return receiver.Ordered
	}
	return
}

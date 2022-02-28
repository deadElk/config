package main

import (
	log "github.com/sirupsen/logrus"
)

func add_PO_PS(_name _Name, inbound *i_PO_PS) (ok bool) {
	switch _, flag := i_ps[_name]; flag {
	case true:
		log.Debugf("Policy Statement '%v' already exist; ACTION: skip.", _name)
		return
	}
	i_ps[_name] = *inbound
	return true
}

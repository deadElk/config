package main

import (
	"github.com/Luzifer/go-dhparam"
	log "github.com/sirupsen/logrus"
)

func generate_DH() (outbound *dhparam.DH) {
	var (
		err error
	)
	switch outbound, err = dhparam.Generate(512, 5, dhparam.GeneratorCallback(nil)); {
	case err != nil:
		log.Fatalf("Error generating DH - '%v'; ACTION: report.", err)
	}
	return
}
func check_DH(inbound *dhparam.DH) (outbound *dhparam.DH) {
	switch {
	case inbound == nil:
		log.Warnf("Nil DH; ACTION: generate a new DH.")
		return generate_DH()
	}
	var (
		err    []error
		status bool
	)
	switch err, status = inbound.Check(); {
	case !status:
		log.Warnf("Error checking DH - '%v'; ACTION: generate a new DH.", err)
		return generate_DH()
	}
	return
}

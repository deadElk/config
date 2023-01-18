package main

import (
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
)

func (receiver *_FQDN) resolve() (outbound []netip.Addr) {
	switch value, err := net.LookupIP(receiver.String()); {
	case err != nil:
		log.Errorf("Error resolving '%v'; ACTION: report.", receiver.String())
		_fatal()
	default:
		for _, z := range value {
			outbound = append(outbound, parse_interface(netip.ParseAddr(z.String())).(netip.Addr))
		}
	}
	return
}

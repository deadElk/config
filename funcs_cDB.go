package main

import (
	"encoding/xml"

	log "github.com/sirupsen/logrus"
)

func read_cDB() (status bool) {
	var (
		xml_db = make(cDB_N_List)
	)
	for _, b := range i_file.list(_dir_etc) {
		var (
			c cDB
		)
		switch err := xml.Unmarshal(*i_file.get(_dir_etc, b), &c); {
		case err != nil:
			log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", b, err)
			status = true
			continue
		}
		xml_db[_Name(b)] = &c
		log.Debugf("configuration file '%v' loaded.", b)
	}
	xml_db.parse()
	return !status
}

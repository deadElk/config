package main

import (
	"encoding/xml"

	log "github.com/sirupsen/logrus"
)

func read_cDB() (not_ok bool) {
	var (
		xml_db = make(cDB_List)
	)
	for _, b := range i_read_file[_S_Dir_List[_dir_list_etc]].sorted {
		var (
			c cDB
		)
		switch err := xml.Unmarshal(i_read_file[_S_Dir_List[_dir_list_etc]].data[b], &c); {
		case err != nil:
			log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", b, err)
			not_ok = true
			continue
		}
		xml_db[b] = &c
		log.Debugf("configuration file '%v' loaded.", b)
	}
	xml_db.parse()
	return !not_ok
}

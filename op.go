package main

import (
	"encoding/xml"

	log "github.com/sirupsen/logrus"
)

func op() (ok bool) {
	var (
		err    error
		xml_db = make(map[_Name]*cDB)
	)
	switch {
	case !read_file():
		log.Warnf("read_file() error; ACTION: fatal.")
		return
	}
	for _, b := range i_read_file[_S_Dir_List[_dir_list_etc]].sorted {
		var (
			c cDB
		)
		switch err = xml.Unmarshal(i_read_file[_S_Dir_List[_dir_list_etc]].data[b], &c); {
		case err != nil:
			log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", b, err)
			continue
		}
		xml_db[b] = &c
		log.Debugf("configuration file '%v' loaded.", b)
	}
	parse_cDB(xml_db)
	parse_iDB()
	parse_GT()
	write_file()
	// switch {
	// case !parse_cDB(xml_db):
	// 	log.Warnf("cDB parse error; ACTION: fatal.")
	// 	return
	// }
	// switch {
	// case !parse_iDB():
	// 	log.Warnf("iDB parse error; ACTION: fatal.")
	// 	return
	// }
	// log.Infof("iDB parsed.")
	// switch {
	// case !parse_GT():
	// 	log.Warnf("GT parse error; ACTION: fatal.")
	// 	return
	// }
	// log.Infof("GTs are parsed.")
	// switch {
	// case !write_file():
	// 	log.Warnf("config upload error.")
	// 	return
	// }
	return err == nil
}

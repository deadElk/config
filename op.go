package main

import (
	"encoding/xml"
	"os"

	log "github.com/sirupsen/logrus"
)

func op() (ok bool) {
	var (
		err error
	)
	func() {
		var (
			xml_db cDB
			data   []byte
		)
		for _, value := range _Defaults[_file_list_config].([]string) {
			switch data, err = os.ReadFile(value); err == nil {
			case false:
				log.Warnf("file '%v' read error: '%v'; ACTION: skip.", value, err)
				continue
			}
			switch err = xml.Unmarshal(data, &xml_db); err == nil {
			case false:
				log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", value, err)
				continue
			}
			log.Debugf("configuration file '%v' loaded.", value)
			switch parse_DB(&xml_db) {
			case false:
				log.Warnf("configuration file '%v' DB parse error: '%v'; ACTION: skip.", value, err)
				continue
			}
			log.Infof("DB '%v' parsed.", xml_db.XMLName.Local)
			return
		}
	}()
	return err == nil
}
func parse_DB(xml_db *cDB) (ok bool) {
	set_loglevel(xml_db.Verbosity)
	switch len(xml_db.GT_Path) == 0 {
	case false:
		_Defaults[_path_GT] = xml_db.GT_Path
	}
	switch read_GT() {
	case false:
		log.Warnf("templates read error; ACTION: skip.")
		return
	}
	set_VI_IPPrefix(xml_db.VI_IPPrefix)
	set_Domain_Name(xml_db.Domain_Name)
	_Defaults[_GT_list] = []_Name{}
	for _, b := range re_period.Split(xml_db.GT_List, -1) {
		_Defaults[_GT_list] = append(_Defaults[_GT_list].([]_Name), _Name(b))
	}
	switch len(xml_db.Upload_Path) == 0 {
	case false:
		_Defaults[_path_out] = xml_db.Upload_Path
	}
	create_AB("OUTER_LIST", &_Service_Attributes{})

	parse_cDB_AB(&xml_db.AB)
	parse_cDB_JA(&xml_db.JA)
	parse_cDB_PL(&xml_db.PL)
	parse_cDB_PS(&xml_db.PS)
	parse_cDB_Peer(&xml_db.Peer)
	parse_cDB_VI(&xml_db.VI)

	// parse_iDB_Peer()
	// parse_iDB_VI_Peer()

	return true
}

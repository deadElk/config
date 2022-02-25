package main

import (
	"encoding/xml"
	"errors"
	"os"

	log "github.com/sirupsen/logrus"
)

func op() (err error) {
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
			set_loglevel(xml_db.Verbosity)
			set_VI_IPPrefix(xml_db.VI_IPPrefix)
			set_Domain_Name(xml_db.Domain_Name)
			_Defaults[_GT_list] = xml_db.GT_List

			switch len(xml_db.Upload_Path) == 0 {
			case false:
				_Defaults[_path_out] = xml_db.Upload_Path
			}
			switch len(xml_db.GT_Path) == 0 {
			case false:
				_Defaults[_path_GT] = xml_db.GT_Path
			}
			switch err = read_GT(); err == nil {
			case false:
				log.Warnf("templates read error; ACTION: skip.")
				continue
			}
			switch err = parse_DB(&xml_db); err == nil {
			case false:
				log.Warnf("configuration file '%v' DB parse error: '%v'; ACTION: skip.", value, err)
				continue
			}
			log.Debugf("DB '%v' parsed.", xml_db.XMLName)
			return
		}
	}()
	// switch err == nil {
	// case false:
	// 	log.Fatalf("cannot continue, error: '%v'; ACTION: exit.", err)
	// 	return
	// }
	// switch err = db_use(); err == nil {
	// case false:
	// 	log.Fatalf("DB use error: '%v'", err)
	// 	return
	// }
	// switch err = config_upload(); err == nil {
	// case false:
	// 	log.Fatalf("config upload error: '%v'", err)
	// 	return
	// }
	// switch err = config_test(); err == nil {
	// case false:
	// 	log.Fatalf("config test error: '%v'", err)
	// 	return
	// }
	return errors.New("nothing to do")
}
func parse_DB(xml_db *cDB) (err error) {
	_ = parse_interface(nil, parse_AB(&xml_db.AB))
	_ = parse_interface(nil, parse_JA(&xml_db.JA))
	return
}

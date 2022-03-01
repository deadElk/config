package main

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"os"
	"text/template"

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
			switch parse_cDB(&xml_db) {
			case false:
				log.Warnf("configuration file '%v' cDB parse error; ACTION: skip.", value)
				continue
			}
			switch parse_iDB() {
			case false:
				log.Warnf("configuration file '%v' iDB parse error; ACTION: skip.", value)
				continue
			}
			log.Infof("DB '%v' parsed.", xml_db.XMLName.Local)
			switch parse_GT() {
			case false:
				log.Warnf("configuration file '%v' GT parse error; ACTION: skip.", value)
				continue
			}
			log.Infof("GTs are parsed.")
			return
		}
	}()
	return err == nil
}
func parse_GT() (ok bool) {
	var (
		err error
	)
	for index, value := range i_peer {
		switch value.Reserved {
		case false:
			func() {
				for _, gt_v := range value.GT_List {
					var (
						vGT  *template.Template
						vBuf bytes.Buffer
					)
					switch vGT, err = template.New(gt_v.String()).Funcs(gt_fm).Parse(i_gt[gt_v].Content.String()); err == nil && vGT != nil {
					case true:
						switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
						case true:
							config[index] = append(config[index], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
						default:
							log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), gt_v, err)
							return
						}
					default:
						log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), gt_v, err)
						return
					}
				}
			}()
		}
	}
	return err == nil
}

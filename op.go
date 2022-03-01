package main

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"os"
	"sort"
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
	switch upload_config() {
	case false:
		log.Warnf("config upload error.")
		return
	}
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
func upload_config() (ok bool) {
	var (
		err error
	)
	var (
		hosts       string
		s_peer_list []int
	)
	for index, value := range config {
		s_peer_list = append(s_peer_list, int(index))
		var (
			fn = _Defaults[_path_out].(string) + "./AS" + index.String()
		)
		switch err = os.WriteFile(fn, value, 0600); err == nil {
		case true:
			log.Debugf("OK '%v'", index)
		case false:
			log.Errorf("Fail '%v' with error '%v'", index, err)
		}
	}
	sort.Ints(s_peer_list)

	for _, value := range s_peer_list {
		var (
			index     = _ASN(value)
			s_public  []string
			s_private []string
		)
		for a := range i_peer[index].AB["O_AS"+_Name(i_peer[index].PName)].Address_Set {
			s_public = append(s_public, a.String())
		}
		for a := range i_peer[index].AB["I_AS"+_Name(i_peer[index].PName)].Address_Set {
			s_private = append(s_private, a.String())
		}
	}

	// 	hosts += func() (outbound string) {
	// 		var (
	// 			ips       string
	// 			publics   []netip.Prefix
	// 			router_id = parse_interface(i_peer[index].Router_ID.Prefix(32)).(netip.Prefix)
	// 		)
	// 		publics = append(publics, router_id)
	// 		for ip_i, ip_v := range i_peer[index].IPPrefix_List {
	// 			switch ip_i == router_id {
	// 			case false:
	// 				ips += tabber(ip_i.String(), 3) + "\t"
	// 			}
	// 			switch ip_v {
	// 			case true:
	// 				publics = append(publics, ip_i)
	// 			}
	// 		}
	// 		for _, ip := range publics {
	// 			outbound += tabber(ip.Addr().String(), 2) +
	// 				"\t####\t" +
	// 				tabber(i_peer[index].PName.String(), 2) + "\t" +
	// 				tabber(i_peer[index].Router_ID.String(), 2) + "\t" +
	// 				tabber(i_peer[index].Hostname.String(), 3) + "\t" +
	// 				tabber(i_peer[index].Manufacturer+" "+i_peer[index].Model, 3) + "\t####\t" +
	// 				ips + "\n"
	// 		}
	// 		outbound += "\n"
	// 		return
	// 	}()
	// }
	//
	// switch err_i := os.WriteFile(_Defaults[_path_out].(string)+"./hosts.txt", []byte(hosts), 0600); err_i == nil {
	// case true:
	// 	log.Infof("OK 'hosts.txt'")
	// case false:
	// 	log.Errorf("Fail 'hosts.txt' with error '%v'", err_i)
	// }

	log.Debugf("\n%s\n", hosts)
	return err == nil
}

package main

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"net/netip"
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
		for _, value := range _Settings[_filename_list_config].([]string) {
			switch data, err = os.ReadFile(value); {
			case err != nil:
				log.Warnf("file '%v' read error: '%v'; ACTION: skip.", value, err)
				continue
			}
			switch err = xml.Unmarshal(data, &xml_db); {
			case err != nil:
				log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", value, err)
				continue
			}
			log.Debugf("configuration file '%v' loaded.", value)
			switch {
			case !parse_cDB(&xml_db):
				log.Warnf("configuration file '%v' cDB parse error; ACTION: skip.", value)
				continue
			}
			switch {
			case !parse_iDB():
				log.Warnf("configuration file '%v' iDB parse error; ACTION: skip.", value)
				continue
			}
			log.Infof("DB '%v' parsed.", xml_db.XMLName.Local)
			switch {
			case !parse_GT():
				log.Warnf("configuration file '%v' GT parse error; ACTION: skip.", value)
				continue
			}
			log.Infof("GTs are parsed.")
			return
		}
	}()
	switch {
	case !upload_config():
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
		switch {
		case value.Reserved:
			continue
		}
		func() {
			for _, gt_v := range value.GT_List {
				var (
					vGT  *template.Template
					vBuf bytes.Buffer
				)
				// switch vGT, err = template.New(gt_v.String()).Funcs(gt_fm).Parse(i_gt[gt_v].Content.String()); err == nil && vGT != nil {
				switch vGT, err = template.New(gt_v.String()).Parse(i_gt[gt_v].Content.String()); {
				case err == nil && vGT != nil:
					switch err = vGT.Execute(&vBuf, value); {
					// case err == nil && vGT != nil:
					case err == nil:
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
	return err == nil
}
func upload_config() (ok bool) {
	var (
		err         error
		i_peer_list []_ASN
		host_list   string
	)

	for a := range i_peer {
		i_peer_list = append(i_peer_list, a)
	}
	sort.Slice(i_peer_list, func(i, j int) bool {
		return i_peer_list[i] < i_peer_list[j]
	})

	for _, b := range i_peer_list {
		var (
			fn = strings_join("/", _Settings[_dirname_out], i_peer[b].ASName)
		)
		switch err = os.WriteFile(fn, config[b], 0600); {
		case err == nil:
			log.Infof("OK '%v'", i_peer[b].ASName)
		default:
			log.Errorf("Fail '%v' with error '%v'", i_peer[b].ASName, err)
		}

		var (
			s_public  []string
			s_private []string
			ip_list   = "\t"
			s_target  = []string{0: i_peer[b].Router_ID.String()}
		)
		for c := range i_peer[b].AB["O_AS"+_Name(i_peer[b].PName)].Set {
			s_public = append(s_public, c.String())
		}
		for c := range i_peer[b].AB["I_AS"+_Name(i_peer[b].PName)].Set {
			s_private = append(s_private, c.String())
		}
		sort.Strings(s_public)
		sort.Strings(s_private)
		for _, d := range s_private {
			ip_list += tabber(d, 3) + "\t"
		}
		for _, d := range s_public {
			s_target = append(s_target, d)
			ip_list += tabber(d, 3) + "\t"
		}
		host_list += func() (outbound string) {
			for _, f := range s_target {
				var (
					host = func() string {
						switch addr, err := netip.ParseAddr(f); {
						case err == nil:
							return addr.String()
						default:
							prefix, _ := netip.ParsePrefix(f)
							return prefix.Addr().String()
						}
					}()
				)
				outbound += tabber(host, 2) +
					"\t####\t" +
					tabber(i_peer[b].PName.String(), 2) + "\t" +
					tabber(i_peer[b].Hostname.String(), 3) + "\t" +
					tabber(i_peer[b].Manufacturer+" "+i_peer[b].Model, 3) + "\t####\t" +
					ip_list + "\n"
			}
			outbound += "\n"
			return
		}()
	}

	switch err = os.WriteFile(_Settings[_dirname_out].(string)+_Settings[_filename_host_list].(string), []byte(host_list), 0600); {
	case err == nil:
		log.Infof("OK '%v'", _Settings[_filename_host_list])
	default:
		log.Errorf("Fail '%v' with error '%v'", _Settings[_filename_host_list], err)
	}

	log.Debugf("\n%s\n", host_list)
	return err == nil
}

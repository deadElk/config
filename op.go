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
		err         error
		i_peer_list []_ASN
		hosts       string
	)

	for a := range i_peer {
		i_peer_list = append(i_peer_list, a)
	}
	sort.Slice(i_peer_list, func(i, j int) bool {
		return i_peer_list[i] < i_peer_list[j]
	})

	for _, b := range i_peer_list {
		var (
			asn = "AS" + pad(b, 10).String()
			fn  = _Defaults[_path_out].(string) + "./" + asn
		)
		switch err = os.WriteFile(fn, config[_ASN(b)], 0600); err == nil {
		case true:
			log.Infof("OK %v", asn)
		case false:
			log.Errorf("Fail '%v' with error '%v'", asn, err)
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
		hosts += func() (outbound string) {
			for _, f := range s_target {
				var (
					host = func() string {
						switch addr, err := netip.ParseAddr(f); err == nil {
						case true:
							return addr.String()
						case false:
							prefix, _ := netip.ParsePrefix(f)
							return prefix.Addr().String()
						}
						return ""
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

	switch err = os.WriteFile(_Defaults[_path_out].(string)+"./hosts.txt", []byte(hosts), 0600); err == nil {
	case true:
		log.Infof("OK 'hosts.txt'")
	case false:
		log.Errorf("Fail 'hosts.txt' with error '%v'", err)
	}

	log.Debugf("\n%s\n", hosts)
	return err == nil
}

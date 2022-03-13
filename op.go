package main

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"net/netip"
	"sort"
	"text/template"

	log "github.com/sirupsen/logrus"
)

func op() (ok bool) {
	var (
		err    error
		xml_db = make(map[_Name]*cDB)
		// data   []byte
	)
	switch {
	case !read_file():
		log.Warnf("file read error; ACTION: fatal.")
		return
	}
	for _, b := range i_read_file[_S_Dir_List[_dir_list_etc]].sorted {
		var (
			// d = i_read_file[_S_Dir_List[_dir_list_etc]].data[b]
			c cDB
		)
		// switch err = xml.Unmarshal(i_read_file[_S_Dir_List[_dir_list_etc]].data[b], xml_db[b]); {
		switch err = xml.Unmarshal(i_read_file[_S_Dir_List[_dir_list_etc]].data[b], &c); {
		case err != nil:
			log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", b, err)
			continue
		}
		xml_db[b] = &c
		log.Debugf("configuration file '%v' loaded.", b)
	}
	switch {
	case !parse_cDB(xml_db):
		log.Warnf("cDB parse error; ACTION: fatal.")
		return
	}
	switch {
	case !parse_iDB():
		log.Warnf("iDB parse error; ACTION: fatal.")
		return
	}
	log.Infof("iDB parsed.")
	switch {
	case !parse_GT():
		log.Warnf("GT parse error; ACTION: fatal.")
		return
	}
	log.Infof("GTs are parsed.")
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
		for _, gt_v := range value.GT_List {
			var (
				vGT  *template.Template
				vBuf bytes.Buffer
			)
			switch vGT, err = template.New(gt_v.String()).Parse(string(i_read_file[_S_Dir_List[_dir_list_GT]].data[gt_v])); {
			case err != nil || vGT == nil:
				log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: ignore.", index.String(), gt_v, err)
				continue
			}
			switch err = vGT.Execute(&vBuf, value); {
			case err != nil:
				log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: ignore.", index.String(), gt_v, err)
				continue
			}
			i_write_file[_S_Dir_List[_dir_list_Config]].data[value.ASName] = append(i_write_file[_S_Dir_List[_dir_list_Config]].data[value.ASName], parse_interface(ioutil.ReadAll(&vBuf)).([]byte)...)
		}
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
		// var (
		// 	fn = strings_join("/", _S_Dir_List[_dir_list_Config], i_peer[b].ASName)
		// )
		// switch err = os.WriteFile(fn, config[b], 0600); {
		// case err == nil:
		// 	log.Infof("OK '%v'", i_peer[b].ASName)
		// default:
		// 	log.Errorf("Fail '%v' with error '%v'", i_peer[b].ASName, err)
		// }

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

	// switch err = os.WriteFile(_S_Dir_List[_dir_list_Config]+_S_filename_host_list, []byte(host_list), 0600); {
	// case err == nil:
	// 	log.Infof("OK '%v'", _S_filename_host_list)
	// default:
	// 	log.Errorf("Fail '%v' with error '%v'", _S_filename_host_list, err)
	// }

	log.Debugf("\n%s\n", host_list)
	return err == nil
}

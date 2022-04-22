package main

import (
	"io/fs"
	"os"
	"os/exec"
	"sort"

	log "github.com/sirupsen/logrus"
)

func (receiver __DN_File_Dir) read() (status bool) {
	for dir := range receiver {
		receiver.check(dir, "")
		var (
			direntry []os.DirEntry
			err      error
			// ext_l    = len(receiver[dir].Ext)
		)
		// switch {
		// case ext_l > 0:
		// 	ext_l++
		// }

		switch direntry, err = os.ReadDir(dir.String()); {
		case err != nil:
			log.Warnf("file '%v' listing error '%v'; ACTION: report.", dir, err)
			// status = true
			continue
		}

		for _, f := range direntry {
			switch {
			case !f.Type().IsRegular():
				log.Debugf("file '%v' is not a regular file; ACTION: skip", f.Name())
				continue
			}
			var (
				// fn = _File_Name(f.Name()[:len(f.Name())-ext_l])
				fn = _File_Name(f.Name())
			)
			switch flag := receiver.read_file(dir, fn); {
			case !flag:
				status = true
				continue
			}
			receiver[dir].Sorted = append(receiver[dir].Sorted, fn)
		}
		sort.Slice(receiver[dir].Sorted, func(i, j int) bool {
			return receiver[dir].Sorted[i] < receiver[dir].Sorted[j]
		})

	}
	return !status
}
func (receiver __DN_File_Dir) get(dir _Dir_Name, file _File_Name) ( /*not_ok bool,*/ outbound *_Content) {
	receiver.check(dir, file)
	return /*!not_ok,*/ receiver[dir].File[file].Content
}
func (receiver __DN_File_Dir) list(dir _Dir_Name) (outbound []_File_Name) {
	receiver.check(dir, "")
	return receiver[dir].Sorted
}
func (receiver __DN_File_Dir) put(dir _Dir_Name, file _File_Name, delimiter string, content any) /*not_ok bool*/ {
	receiver.check(dir, file)
	var (
		v_Content = _Content(interface_string(delimiter, content))
	)
	receiver[dir].File[file].Content = &v_Content
	receiver[dir].File[file].Flag = true
	// return !not_ok
}
func (receiver __DN_File_Dir) append(dir _Dir_Name, file _File_Name, delimiter string, content any) /*not_ok bool*/ {
	receiver.check(dir, file)
	var (
		v_Content = _Content(join_string(delimiter, receiver[dir].File[file].Content, content))
	)
	receiver[dir].File[file].Content = &v_Content
	receiver[dir].File[file].Flag = true
	// return !not_ok
}
func (receiver __DN_File_Dir) write() (not_ok bool) {
	_check()
	var (
		d_mode = fs.FileMode(os.ModeDir | 0755)
		f_mode = map[bool]fs.FileMode{
			false: 0644,
			true:  0755,
		}
	)
	for dir, b := range receiver {
		switch err := os.MkdirAll(dir.String(), d_mode); {
		case err != nil:
			log.Errorf("directory '%v' create error '%v'; ACTION: report.", dir, err)
			not_ok = true
			continue
		}
		for file, d := range b.File {
			switch {
			case !d.Flag:
				log.Debugf("file '%v' hasn't changed; ACTION: report.", file)
				continue
			}
			var (
				v_full_pfn = dir.a(_Dir_Name(file))
			)
			switch err := os.WriteFile(v_full_pfn.String(), *d.Content, f_mode[d.Exec]); {
			case err != nil:
				log.Errorf("file '%v' write error '%v'; ACTION: report.", v_full_pfn, err)
				not_ok = true
				continue
			}
			d.Flag = false
		}
	}
	return !not_ok
}
func (receiver __DN_File_Dir) check(dir _Dir_Name, file _File_Name) {
	switch _, flag := receiver[dir]; {
	case !flag:
		log.Debugf("Dir '%v' definition doesn't exist; ACTION: create.", dir)
		receiver[dir] = &i_Dir_Data{File: __FN_File_Data{}}
	}
	switch {
	case receiver[dir].File == nil:
		receiver[dir].File = __FN_File_Data{}
	}
	switch {
	case len(file) != 0:
		switch _, flag := receiver[dir].File[file]; {
		case !flag:
			log.Debugf("Dir '%v', File '%v' definition doesn't exist; ACTION: create.", dir, file)
			// receiver.read_file(dir, file, ext)
			receiver[dir].File[file] = &i_File_Data{Content: &_Content{}}
		}
	}
}
func (receiver __DN_File_Dir) read_file(dir _Dir_Name, file _File_Name) (status bool) {
	receiver.check(dir, file)
	var (
		content    _Content
		v_full_pfn = dir.a(file)
		v_Flag     = receiver[dir].File[file].Flag
		err        error
	)
	switch content, err = os.ReadFile(v_full_pfn.String()); {
	case err != nil:
		log.Warnf("file '%v' read error '%v'; ACTION: report.", v_full_pfn, err)
		return
	}
	switch {
	case receiver[dir].Type == _Type_template || receiver[dir].File[file].Type == _Type_template:
		content.trim_space()
	}
	receiver.put(dir, file, "", content)
	receiver[dir].File[file].Flag = v_Flag
	return true
}

func (receiver _Dir_Name) a(inbound ...any) (outbound _Dir_Name) {
	var (
		interim   = []string{receiver.String()}
		delimiter = "/"
	)
	for _, b := range inbound {
		interim = append(interim, interface_string(delimiter, b))
	}
	return _Dir_Name(join_string(delimiter, interim))
}
func (receiver _File_Name) a(inbound ...any) (outbound _File_Name) {
	var (
		interim   = []string{receiver.String()}
		delimiter = "."
	)
	for _, b := range inbound {
		interim = append(interim, interface_string(delimiter, b))
	}
	return _File_Name(join_string(delimiter, interim))
}
func (receiver _File_Name) aa(delimiter string, inbound ...any) (outbound _File_Name) {
	var (
		interim = []string{receiver.String()}
	)
	for _, b := range inbound {
		interim = append(interim, interface_string(delimiter, b))
	}
	return _File_Name(join_string(delimiter, interim))
}

func (receiver _File_Name) external(args ...string) (outbound _Content) {
	_check()
	var (
		err error
	)
	switch outbound, err = exec.Command(receiver.String(), args...).Output(); {
	case err != nil:
		log.Warnf("external programm '%v' execution error '%v'; ACTION: ignore.", receiver, err)
		return nil
	}
	switch {
	case outbound == nil:
		return _Content{}
	}
	return
}
func (receiver __DN_File_Dir) fn(dir _Dir_Name, file _File_Name) (outbound _File_Name) {
	receiver.check(dir, file)
	return _File_Name(dir.a(file))
}
func (receiver __DN_File_Dir) e(dir _Dir_Name, file _File_Name) {
	receiver.check(dir, file)
	receiver[dir].File[file].Exec = true
}
func (receiver __LN_Link_Name) l(source _Link_Name, destination _Link_Name) {
	receiver[destination] = source
}
func (receiver __LN_Link_Name) write() {
	for a, b := range receiver {
		switch err := os.Symlink(b.String(), a.String()); err == nil {
		case true:
			log.Debugf("Symlink from '%v' to '%v'; RESULT: '%v'.", a, b, os.Symlink(b.String(), a.String()))
		case false:
			log.Debugf("Symlink from '%v' to '%v'; RESULT: '%v'.", a, b, os.Symlink(b.String(), a.String()))
		}
		// _ = os.Symlink(b.String(), a.String())
		// log.Infof("Symlink from '%v' to '%v'; ACTION: create.", a, b)
		// switch value, err := os.Readlink(a.String()); {
		// case err == nil && value == b.String():
		// 	log.Infof("Symlink from '%v' to '%v' already exist; ACTION: skip.", a, b)
		// 	return
		// case err != nil:
		// 	log.Infof("Symlink from '%v' to '%v' error '%v'; ACTION: skip.", a, b, err)
		// 	// switch err = os.Remove(a.String()); {
		// 	// case err != nil:
		// 	// 	log.Warnf("Symlink from '%v' to '%v' remove error '%v'; ACTION: skip.", a, b, err)
		// 	// }
		// }
		// switch err := os.Symlink(b.String(), a.String()); {
		// case err != nil:
		// 	log.Infof("Symlink from '%v' to '%v' create error '%v'; ACTION: skip.", a, b, err)
		// }
	}
}

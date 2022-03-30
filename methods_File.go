package main

import (
	"bytes"
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
			ext_l    = len(receiver[dir].Ext)
		)
		switch {
		case ext_l > 0:
			ext_l++
		}

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
				content _Content
				ffn     = join_string("/", dir, f.Name())
				fn      = _File_Name(f.Name()[:len(f.Name())-ext_l])
				f_fn    bool
			)
			switch content, err = os.ReadFile(ffn); {
			case err != nil:
				log.Warnf("file '%v' read error '%v'; ACTION: report.", ffn, err)
				status = true
				continue
			}
			switch receiver[dir].Ext {
			case receiver[_dir_GT].Ext:
				content.trim_space()
			}
			switch _, flag := receiver[dir].File[fn]; {
			case flag:
				f_fn = receiver[dir].File[fn].Flag
			}
			receiver.put(dir, fn, "", content)
			receiver[dir].File[fn].Flag = f_fn
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
	switch _, flag := receiver[dir].File[file]; {
	case !flag:
		return
	}
	return /*!not_ok,*/ receiver[dir].File[file].Content
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
		d_mode = fs.FileMode(os.ModeDir | 0700)
		f_mode = map[bool]fs.FileMode{
			false: 0600,
			true:  0700,
		}
	)
	for a, b := range receiver {
		switch err := os.MkdirAll(a.String(), d_mode); {
		case err != nil:
			log.Errorf("directory '%v' create error '%v'; ACTION: report.", a, err)
			not_ok = true
			continue
		}
		for c, d := range b.File {
			switch {
			case !d.Flag:
				log.Debugf("file '%v' hasn't changed; ACTION: report.", c)
				continue
			}
			var (
				g = join_string("/", a, join_string(".", c, b.Ext))
			)
			switch err := os.WriteFile(g, *d.Content, f_mode[d.Exec]); {
			case err != nil:
				log.Errorf("file '%v' write error '%v'; ACTION: report.", g, err)
				not_ok = true
				continue
			}
		}
	}
	return !not_ok
}
func (receiver __DN_File_Dir) check(dir _Dir_Name, file _File_Name) /*not_ok bool*/ {
	switch _, flag := receiver[dir]; {
	case !flag:
		log.Debugf("Dir '%v' definition doesn't exist; ACTION: create.", dir)
		receiver[dir] = &i_File_Dir{Flag: true, File: __FN_File_Data{}}
	}
	switch {
	case len(file) != 0:
		switch _, flag := receiver[dir].File[file]; {
		case !flag:
			log.Debugf("File '%v' definition in Dir '%v' doesn't exist; ACTION: create.", dir, file)
			receiver[dir].File[file] = &i_File_Data{Content: &_Content{}}
			// receiver[dir].File[file].Content = &_Content{}
			// receiver[dir].File[file].Flag = true
		}
	}
}
func (receiver _Dir_Name) a(inbound ..._Dir_Name) (outbound _Dir_Name) {
	// return _Dir_Name(join_string("/", receiver, join_string("/", inbound...)))
	var (
		interim   = []_Dir_Name{receiver}
		delimiter = "/"
	)
	interim = append(interim, inbound...)
	var (
		inbounds = len(interim) - 1
		buffer   = new(bytes.Buffer)
	)
	for a, b := range interim {
		switch {
		case len(b) == 0:
			continue
		}
		buffer.WriteString(b.String())
		switch {
		case a < inbounds:
			buffer.WriteString(delimiter)
		}
	}
	return _Dir_Name(buffer.String())
}
func (receiver _File_Name) a(delimiter string, inbound ..._File_Name) (outbound _File_Name) {
	var (
		interim = []_File_Name{receiver}
	)
	interim = append(interim, inbound...)
	var (
		inbounds = len(interim) - 1
		buffer   = new(bytes.Buffer)
	)
	for a, b := range interim {
		switch {
		case len(b) == 0:
			continue
		}
		buffer.WriteString(b.String())
		switch {
		case a < inbounds:
			buffer.WriteString(delimiter)
		}
	}
	return _File_Name(buffer.String())
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
	switch _, flag := receiver[dir].File[file]; {
	case !flag:
		return
	}
	return _File_Name(join_string("/", dir, join_string(".", file, receiver[dir].Ext)))
}
func (receiver __DN_File_Dir) e(dir _Dir_Name, file _File_Name) {
	receiver.check(dir, file)
	receiver[dir].File[file].Exec = true
}
func (receiver __DN_File_Dir) l(dir _Dir_Name, file _File_Name, link _File_Name) {
	receiver.check(dir, file)
}

package main

type __FN_File_Data map[_File_Name]*i_File_Data
type __DN_File_Dir map[_Dir_Name]*i_File_Dir

// file storage
type i_File_Dir struct {
	Flag   bool
	Ext    _Name
	Link   _Name // ln -s Link to _Name
	Sorted []_File_Name
	File   __FN_File_Data
}
type i_File_Data struct {
	Flag    bool
	Ext     _Name
	Link    _Name // ln -s Link to _Name
	Exec    bool
	Content *_Content
}

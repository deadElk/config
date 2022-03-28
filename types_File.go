package main

type __FN_File_Data_Content map[_File_Name]*i_File_Data_Content
type __DN_File_Data map[_Dir_Name]*i_File_Data

// file i/o
type i_File_Data struct {
	Flag   bool
	Ext    _Name
	Sorted []_File_Name
	File   __FN_File_Data_Content
}
type i_File_Data_Content struct {
	Flag    bool
	Ext     _Name
	Content *_Content
}

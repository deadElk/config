package main

type __FN_File_Data map[_File_Name]*i_File_Data //
type __DN_File_Dir map[_Dir_Name]*i_Dir_Data    //
type __LN_Link_Name map[_Link_Name]_Link_Name   //
type _Dir_Name _Name                            //
type _Link_Name _Name                           //
type _File_Name _Name                           //

type i_Dir_Data struct {
	Flag      bool           //
	Recursive bool           //
	Type      _Type          //
	Sorted    []_File_Name   //
	File      __FN_File_Data //
}
type i_File_Data struct {
	Flag    bool      //
	Type    _Type     //
	Exec    bool      //
	Content *_Content //
}

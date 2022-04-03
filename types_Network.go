package main

import (
	"net/netip"
	"net/url"
)

type _INet_IPAddr struct{ *netip.Addr }                         // Why returning String() 'invalid IP' ???? What for???? Why not just return an empty String() ????
type _INet_IPPrefix struct{ *netip.Prefix }                     // Why returning String() 'invalid IP' ???? What for???? Why not just return an empty String() ????
type _INet_Port uint16                                          //
type _INet_Protocol string                                      //
type _INet_Routing uint32                                       //
type _INet_URL struct{ *url.URL }                               //
type _Inet_ASN uint32                                           //
type _Mask string                                               //
type _VI_Conn_ID _INet_Routing                                  //
type _VI_ID _INet_Routing                                       //
type __A_BGP_Group_Neighbor map[netip.Addr]*_BGP_Group_Neighbor //
type __N_BGP_Group map[_Name]*_BGP_Group                        //
type _URI string                                                //

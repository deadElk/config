package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
)

// Note: XML database is a compromise between el odmin and a config-generator
// the root of all evil premature optimization is

// TODO: implement Junos $1$ (md5? user passwords), $9$ (sha? user passwords and PSKs) and other encryption methods
// TODO: implement DB validation and maximum possible autofill
// TODO: implement template list customization
// TODO: this program is just adapter written on golang to gotemplate defined in config

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.
type _AS_Number uint32
type _Address_Book map[string]map[netip.Prefix]bool
type _RM_Index [_rm_max + 1]uint32
type _Template_Name string
type _RI_Name string
type _IF_Name string
type _IF_Index uint
type _IP_Address_Index uint
type _VI_Index uint
type _VI_Index_Padded_Name string
type _VI_Peer_Index uint
type _IF_Communication string
type _VI_Type string
type _GW_Type string
type _GW_Name string

type sDB struct {
	XMLName     xml.Name       `xml:"AS4200240XXX"`
	Peer        []sDB_Peer     `xml:"peer_list>peer"`
	VI          []sDB_VI       `xml:"VI_list>VI"`
	Template    []sDB_Template `xml:"template_list>template"`
	VI_IPPrefix netip.Prefix   `xml:"VI_IPPrefix,attr"`
	Reserved    bool           `xml:"reserved,attr"`
	Description string         `xml:"description,attr"`
	Verbosity   string         `xml:"verbosity,attr"`
}
type sDB_Template struct {
	Name        _Template_Name `xml:"name,attr"`
	Content     string         `xml:",chardata"`
	Reserved    bool           `xml:"reserved,attr"`
	Description string         `xml:"description,attr"`
}
type sDB_Peer struct {
	ASN          _AS_Number    `xml:"ASN,attr"`
	RI           []sDB_Peer_RI `xml:"RI"`
	Hostname     string        `xml:"hostname,attr"`
	Version      string        `xml:"version,attr"`
	Manufacturer string        `xml:"manufacturer,attr"`
	Model        string        `xml:"model,attr"`
	Serial       string        `xml:"serial,attr"`
	Config_Patch string        `xml:"config_patch"`
	Root         string        `xml:"root,attr"`
	Reserved     bool          `xml:"reserved,attr"`
	Description  string        `xml:"description,attr"`
}
type sDB_Peer_RI struct {
	Name        _RI_Name         `xml:"name,attr"`
	RT          []sDB_Peer_RI_RT `xml:"RT"`
	IF          []sDB_Peer_RI_IF `xml:"IF"`
	Reserved    bool             `xml:"reserved,attr"`
	Description string           `xml:"description,attr"`
}
type sDB_Peer_RI_IF struct {
	Name          _IF_Name                   `xml:"name,attr"`
	Index         _IF_Index                  `xml:"index,attr"`
	Communication _IF_Communication          `xml:"communication,attr"`
	Address       []sDB_Peer_RI_IF_Address   `xml:"address"`
	Proxy_ARP     []sDB_Peer_RI_IF_Proxy_ARP `xml:"proxy_arp"`
	Disable       bool                       `xml:"disable,attr"`
	Reserved      bool                       `xml:"reserved,attr"`
	Description   string                     `xml:"description,attr"`
}
type sDB_Peer_RI_IF_Address struct {
	Index       _IP_Address_Index `xml:"index,attr"`
	IPPrefix    netip.Prefix      `xml:"ipprefix,attr"`
	NAT         netip.Addr        `xml:"NAT,attr"`
	DHCP        bool              `xml:"dhcp,attr"`
	Reserved    bool              `xml:"reserved,attr"`
	Description string            `xml:"description,attr"`
}
type sDB_Peer_RI_IF_Proxy_ARP struct {
	IPPrefix    netip.Prefix `xml:"ipprefix,attr"`
	NAT         netip.Addr   `xml:"NAT,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description string       `xml:"description,attr"`
}
type sDB_Peer_RI_RT struct {
	Identifier  netip.Prefix        `xml:"identifier,attr"`
	GW          []sDB_Peer_RI_RT_GW `xml:"GW"`
	Reserved    bool                `xml:"reserved,attr"`
	Description string              `xml:"description,attr"`
}
type sDB_Peer_RI_RT_GW struct {
	IP          netip.Addr `xml:"ip,attr"`
	IF          _IF_Name   `xml:"IF,attr"`
	Table       string     `xml:"table,attr"`
	Discard     bool       `xml:"discard,attr"`
	Type        _GW_Type   `xml:"type,attr"`
	Reserved    bool       `xml:"reserved,attr"`
	Description string     `xml:"description,attr"`
}
type sDB_VI struct {
	Index         _VI_Index         `xml:"index,attr"`
	Type          _VI_Type          `xml:"type,attr"`
	Communication _IF_Communication `xml:"communication,attr"`
	Route_Metric  uint              `xml:"route_metric,attr"`
	Peer          []sDB_VI_Peer     `xml:"peer"`
	PSK           string            `xml:"PSK,attr"`
	Reserved      bool              `xml:"reserved,attr"`
	Description   string            `xml:"description,attr"`
}
type sDB_VI_Peer struct {
	Index         _VI_Peer_Index `xml:"index,attr"`
	ASN           _AS_Number     `xml:"ASN,attr"`
	RI            _RI_Name       `xml:"RI,attr"`
	IF            _IF_Name       `xml:"IF,attr"`
	IP            netip.Addr     `xml:"IP,attr"`
	Local_Address bool           `xml:"local_address,attr"`
	Dynamic       bool           `xml:"dynamic,attr"`
	No_NAT        bool           `xml:"no_nat,attr"`
	Hub           bool           `xml:"hub,attr"`
	Inner_RI      _RI_Name       `xml:"inner_RI,attr"`
	Reserved      bool           `xml:"reserved,attr"`
	Description   string         `xml:"description,attr"`
}
type wDB_Host struct {
	AS_Padded_Name string
	RI             map[_RI_Name]wDB_Host_RI // Peer_RI_Name
	IF_RI          map[_IF_Name]_RI_Name    // interface name to RI mapping
	Hostname       string
	Version        string
	Major          float64
	IKE_GCM        bool
	Manufacturer   string
	Model          string
	Serial         string
	Config_Patch   string
	Root           string
	Reserved       bool
	Description    string

	ASN          _AS_Number
	RM_Index     *_RM_Index
	Address_Book *_Address_Book
	VI           map[_VI_Index]*wDB_VI
	VI_Left      map[_VI_Index]*wDB_VI_Peer
	VI_Right     map[_VI_Index]*wDB_VI_Peer
}
type wDB_Host_RI struct {
	// Name        string
	RT          map[netip.Prefix]wDB_Host_RI_RT // Peer_RI_RT_Identifier
	IF          map[_IF_Name]wDB_Host_RI_IF     // Peer_RI_IF_Name
	IF_Index    map[_IF_Index]_IF_Name          // interface index to name mapping
	Reserved    bool
	Description string
}
type wDB_Host_RI_IF struct {
	// Name        string
	Index         _IF_Index
	Communication _IF_Communication
	Address       map[netip.Addr]wDB_Host_RI_IF_Address   // Peer_RI_IF_Address_IPPrefix
	Proxy_ARP     map[netip.Addr]wDB_Host_RI_IF_Proxy_ARP // Peer_RI_IF_Proxy_ARP_IPPrefix
	Address_Index map[_IP_Address_Index]netip.Addr        // interface's address index
	Disable       bool
	Reserved      bool
	Description   string
}
type wDB_Host_RI_IF_Address struct {
	Index       _IP_Address_Index
	IPPrefix    netip.Prefix
	NAT         netip.Addr
	DHCP        bool
	Reserved    bool
	Description string
}
type wDB_Host_RI_IF_Proxy_ARP struct {
	IPPrefix    netip.Prefix
	NAT         netip.Addr
	Reserved    bool
	Description string
}
type wDB_Host_RI_RT struct {
	// Identifier  netip.Prefix
	GW          map[_GW_Name]wDB_Host_RI_RT_GW // Peer_RI_RT_GW (use IP/Interface/Table/Discard as string Index)
	Reserved    bool
	Description string
}
type wDB_Host_RI_RT_GW struct {
	IP          netip.Addr // name candidate priority 1
	IF          _IF_Name   // name candidate priority 2
	Table       string     // name candidate priority 3
	Discard     bool       // name candidate priority 0
	Type        _GW_Type   // fill type appropriately
	Reserved    bool
	Description string
}
type wDB_VI struct {
	VI_Index_Padded_Name _VI_Index_Padded_Name
	// Index         uint
	Type          _VI_Type
	Communication _IF_Communication
	PSK           string
	Route_Metric  uint
	// Peer          map[_VI_Peer_Index]*wDB_VI_Peer // VI_Peer_Index
	Peer_AS_Index map[_VI_Peer_Index]_AS_Number
	IPPrefix      netip.Prefix
	Reserved      bool
	Description   string
}
type wDB_VI_Peer struct {
	Index          _VI_Peer_Index
	ASN            _AS_Number
	RI             _RI_Name
	IF             _IF_Name
	IP             netip.Addr
	NAT            netip.Addr
	Use_NAT        bool
	Local_Address  bool
	Dynamic        bool
	No_NAT         bool
	Hub            bool
	Inner_RI       _RI_Name
	Inner_IPPrefix netip.Prefix
	Reserved       bool
	Description    string
}
type wDB_Template struct { // Name        _Template_Name
	Content     string
	Reserved    bool
	Description string
}

const (
	// _juniper_mgmt_RI _RI_Name = "mgmt_junos"
	// _juniper_mgmt_IF string = "fxp0.0"
	_default_loglevel                      = log.InfoLevel
	_service             string            = "config"
	_serviced                              = _service /*+ "d"*/
	_SERVICE             string            = "CONFIG"
	_SERVICED                              = _SERVICE /*+ "D"*/
	_hash_Size           int               = 512 / 8
	_passwd_Z            string            = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	_passwd_z            string            = "abcdefghijklmnopqrstuvwxyz"
	_passwd_0            string            = "0123456789"
	_passwd_oops         string            = "_" // carefully with special symbols
	_passwd                                = _passwd_Z + _passwd_z + _passwd_0 + _passwd_oops
	_default_vi_ipprefix string            = "10.90.0.0/16"
	_juniper_default_RI  _RI_Name          = "master"
	_juniper_mgmt_RI     _RI_Name          = "master"
	_juniper_mgmt_IF     string            = "lo0.0"
	_gw_hop              _GW_Type          = "hop"
	_gw_interface        _GW_Type          = "interface"
	_gw_table            _GW_Type          = "table"
	_gw_discard          _GW_Type          = "discard"
	_vi_ti               _VI_Type          = "ti"
	_vi_gr               _VI_Type          = "gr"
	_vi_lt               _VI_Type          = "lt"
	_default_vi                            = _vi_ti
	_if_comm_ptp         _IF_Communication = "ptp"
	_if_comm_ptmp        _IF_Communication = "ptmp"
	_default_vi_comm                       = _if_comm_ptp
	_default_if_comm                       = _if_comm_ptmp
	_node0               string            = "node0"
	_node1               string            = "node1"
	_left                string            = "left"
	_right               string            = "right"
	_rm_bits             uint              = 2
	_rm_max                                = 32/_rm_bits - 1
)

var (
	hash_cache       sync.Map
	re_caps          = regexp.MustCompile(`[A-Z]`)
	template_FuncMap = template.FuncMap{"sum_uint32": sum_uint32_template_FuncMap}
	_loglevel        = _default_loglevel
	rm_index         = func() (outbound _RM_Index) {
		for shift, interim := 0, 0; interim <= int(_rm_max); interim, shift = interim+1, shift+int(_rm_bits) {
			outbound[interim] = 1 << shift
		}
		return
	}()
	address_book  = make(_Address_Book)
	vi_ipprefix   netip.Prefix
	vi_ip_shift   _VI_Index
	i_db_host     = make(map[_AS_Number]*wDB_Host)                      // Peer_ASN
	i_db_vi       = make(map[_VI_Index]*wDB_VI)                         // VI_Index
	i_db_vi_peer  = make(map[_VI_Index]map[_VI_Peer_Index]*wDB_VI_Peer) // VI_Peer_Index
	i_db_template = make(map[_Template_Name]*wDB_Template)              // Template_Name
	config        = make(map[_AS_Number]bytes.Buffer)                   // resulting configs
)

func (inbound _AS_Number) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func get_vi_ipprefix(vi_shift _VI_Index, peer_shift _VI_Peer_Index) (outbound netip.Prefix) {
	var (
		b = make([]byte, 4)
	)
	binary.BigEndian.PutUint32(b, uint32(vi_ip_shift)+uint32(vi_shift)*4+uint32(peer_shift))
	return netip.PrefixFrom(parse_interface(netip.AddrFromSlice(b)).(netip.Addr), 30)
}
func set_vi_ipprefix(inbound netip.Prefix) {
	switch inbound.IsValid() {
	case true:
		vi_ipprefix = inbound
	default:
		switch candidate, err := netip.ParsePrefix(_default_vi_ipprefix); err == nil {
		case true:
			vi_ipprefix = candidate
		default:
			return
		}
	}
	vi_ip_shift = _VI_Index(binary.BigEndian.Uint32(vi_ipprefix.Addr().AsSlice()))
}
func sum_uint32_template_FuncMap(inbound ...uint32) (outbound uint32) {
	switch len(inbound) {
	case 0:
		return 0
	case 1:
		return inbound[0]
	}
	for index := 0; index < len(inbound); index++ {
		outbound += inbound[index]
	}
	return
}
func sanitize_string(inbound *string) (outbound string) {
	for _, value := range strings.Split(*inbound, "\n") {
		outbound += strings.TrimSpace(value) + "\n"
	}
	return
}
func add_to_address_book_ipset(public, private bool, ab_name string, ip ...interface{}) {
	for _, address := range ip {
		var (
			interim netip.Prefix
			bits    = 32
		)
		switch value := (address).(type) {
		case netip.Addr:
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (is_private && !public) {
			case true:
				continue
			}
			switch value.Is6() {
			case true:
				bits = 128
			}
			interim, _ = value.Prefix(bits)
		case netip.Prefix:
			switch value.IsValid() {
			case false:
				continue
			}
			interim = value
		// case string:
		// 	continue
		default:
			continue
		}
		switch _, flag := address_book[ab_name]; flag {
		case false:
			// address_book[ab_name] = make(map[netip.Prefix]bool)
			address_book[ab_name] = map[netip.Prefix]bool{
				interim: true,
			}
			continue
		}
		switch _, flag := address_book[ab_name][interim]; flag {
		case false:
			address_book[ab_name][interim] = true
		}
	}
}
func hash(inbound *string) (outbound _ID) {
	var (
		value, flag = hash_cache.Load(*inbound)
	)
	switch {
	case flag && value.([_hash_Size]uint8) != outbound:
		return value.([_hash_Size]uint8)
	case flag:
		log.Warnf("Daemon: hash error - zero result from hash_cache.Load(%+v); ACTION: try to recover.", inbound)
	}
	switch value = sha3.Sum512([]uint8(*inbound)); value.([_hash_Size]uint8) != outbound {
	case true:
		hash_cache.Store(*inbound, value.([_hash_Size]uint8))
		return value.([_hash_Size]uint8)
	default:
		log.Panicf("Daemon: hash error - zero result from hash(%+v); ACTION: panic.", []uint8(*inbound))
	}
	return
}
func generate_passwd(length uint) string {
	var (
		ret = make([]byte, length)
	)
	for i := 0; i < int(length); i++ {
		switch next, err := rand.Int(rand.Reader, big.NewInt(int64(len(_passwd)))); err == nil && next != nil {
		case true:
			ret[i] = _passwd[next.Int64()]
		default:
			log.Panicf("rand.Int error: %#v", err)
		}
	}
	return string(ret)
}
func log_setlevel(inbound ...*string) {
	switch len(inbound) > 0 {
	case true:
		switch loglevel, err := log.ParseLevel(*inbound[0]); err == nil {
		case true:
			log.SetLevel(loglevel)
		default:
			log.SetLevel(_default_loglevel)
			// log.Warnf("verbosity level '%v' is not supported; ACTION: use '%v'.", *inbound[0], log.GetLevel())
		}
	default:
		log.SetLevel(_loglevel)
	}
}
func parse_interface(inbound interface{}, skip interface{}) interface{} {
	switch skip.(type) {
	case error:
		switch skip == nil {
		case false:
			log.Debugf("'%v'", skip)
		}
	case bool:
		switch skip {
		case false:
			log.Debugf("'%v'", skip)
		}
	}
	return inbound
}
func parse_interface_error(inbound interface{}, skip interface{}) (outbound interface{}) {
	switch skip.(type) {
	case error:
		switch skip == nil {
		case false:
			log.Debugf("'%v'", skip)
			return
		}
	case bool:
		switch skip {
		case false:
			log.Debugf("'%v'", skip)
			return
		}
	}
	return inbound
}
func parse_RI(inbound *_RI_Name) _RI_Name {
	switch len(*inbound) == 0 {
	case true:
		return _juniper_default_RI
	}
	return *inbound
}
func init() {
	log.SetLevel(_loglevel)
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    false,
		FullTimestamp:    true,
		PadLevelText:     true,
		ForceQuote:       true,
		QuoteEmptyFields: true,
		TimestampFormat:  time.RFC3339Nano,
		// TimestampFormat: "02 15:04:05 MST",
	})
	log.SetReportCaller(true)
}
func read_file(inbound *string, outbound *[]byte) (err error) {
	var (
		inbound_link *os.File
	)
	switch inbound_link, err = os.Open(*inbound); err == nil {
	case true:
		defer func() {
			switch inbound_link != nil {
			case true:
				switch defer_err := inbound_link.Close(); defer_err != nil {
				case true:
					log.Debugf(".Close() error: '%v'", defer_err)
					switch err == nil && defer_err != nil {
					case true:
						err = defer_err
					}
				}
			}
		}()
		switch *outbound, err = io.ReadAll(inbound_link); err == nil {
		case false:
			log.Warnf("file '%v' read error: '%v'; ACTION: skip.", inbound, err)
		}
	default:
		log.Debugf("file '%v' open error: '%v'; ACTION: skip.", inbound, err)
	}
	return
}
func read_db() (err error) {
	var (
		configuration_files = []string{
			"./" + _serviced + ".xml",
			"/usr/local/opt/etc/" + _serviced + ".xml",
			"/opt/etc/" + _serviced + ".xml",
			"/usr/local/etc/" + _serviced + ".xml",
			"/etc/" + _serviced + ".xml",
		}
		xml_db sDB
		data   []byte
	)
	for _, value := range configuration_files {
		switch err = read_file(&value, &data); err == nil {
		case true:
			switch err = xml.Unmarshal(data, &xml_db); err == nil {
			case true:
				log.Debugf("configuration file '%v' loaded.", value)
				switch err = parse_db(&xml_db); err == nil {
				case true:
					log.Debugf("DB '%v' parsed.", xml_db.XMLName)
					return nil
				case false:
					log.Warnf("DB parse error: '%v'; ACTION: next.", err)
				}
			default:
				log.Warnf("configuration file '%v' parse error: '%v'; ACTION: skip.", value, err)
			}
		}
	}
	return errors.New("no configuration found")
}
func parse_db(xml_db *sDB) (err error) {
	log_setlevel(&xml_db.Verbosity)
	set_vi_ipprefix(xml_db.VI_IPPrefix)
	for _, i_db_host_v := range xml_db.Peer {
		switch i_db_host_v.Reserved {
		case false:
			var (
				i_db_host_if_ri_v    = make(map[_IF_Name]_RI_Name)
				i_db_host_as_name_v  = i_db_host_v.ASN.String()
				i_db_host_version_i  = re_caps.Split(i_db_host_v.Version, -1)
				i_db_host_major_v, _ = strconv.ParseFloat(i_db_host_version_i[0], 64)
				i_db_host_ike_gcm_v  = i_db_host_major_v >= 12.3
			)
			i_db_host[i_db_host_v.ASN] = &wDB_Host{
				ASN:            i_db_host_v.ASN,
				AS_Padded_Name: fmt.Sprintf("%10d", i_db_host_as_name_v),
				RI: func() (i_db_host_ri_o map[_RI_Name]wDB_Host_RI) {
					i_db_host_ri_o = make(map[_RI_Name]wDB_Host_RI)
					for _, i_db_host_ri_v := range i_db_host_v.RI {
						switch i_db_host_ri_v.Reserved {
						case false:
							var (
								i_db_host_ri_if_index_v = make(map[_IF_Index]_IF_Name)
							)
							i_db_host_ri_o[i_db_host_ri_v.Name] = wDB_Host_RI{
								RT: func() (i_db_host_ri_rt_o map[netip.Prefix]wDB_Host_RI_RT) {
									i_db_host_ri_rt_o = make(map[netip.Prefix]wDB_Host_RI_RT)
									for _, i_db_host_ri_rt_v := range i_db_host_ri_v.RT {
										switch i_db_host_ri_rt_v.Reserved {
										case false:
											i_db_host_ri_rt_o[i_db_host_ri_rt_v.Identifier] = wDB_Host_RI_RT{
												GW: func() (i_db_host_ri_rt_gw_o map[_GW_Name]wDB_Host_RI_RT_GW) {
													i_db_host_ri_rt_gw_o = make(map[_GW_Name]wDB_Host_RI_RT_GW)
													for _, i_db_host_ri_rt_gw_v := range i_db_host_ri_rt_v.GW {
														switch i_db_host_ri_rt_gw_v.Reserved {
														case false:
															var (
																gw_i string
															)
															switch {
															case i_db_host_ri_rt_gw_v.Type == _gw_discard:
																gw_i = string(_gw_discard)
															case i_db_host_ri_rt_gw_v.Type == _gw_hop && i_db_host_ri_rt_gw_v.IP.IsValid():
																gw_i = i_db_host_ri_rt_gw_v.IP.String()
															case i_db_host_ri_rt_gw_v.Type == _gw_interface && len(i_db_host_ri_rt_gw_v.IF) != 0:
																gw_i = string(i_db_host_ri_rt_gw_v.IF)
															case i_db_host_ri_rt_gw_v.Type == _gw_table && len(i_db_host_ri_rt_gw_v.Table) != 0:
																gw_i = i_db_host_ri_rt_gw_v.Table
															case len(i_db_host_ri_rt_gw_v.Type) == 0:
																switch {
																case i_db_host_ri_rt_gw_v.Discard:
																	gw_i = string(_gw_discard)
																	i_db_host_ri_rt_gw_v.Type = _gw_discard
																case i_db_host_ri_rt_gw_v.IP.IsValid():
																	gw_i = i_db_host_ri_rt_gw_v.IP.String()
																	i_db_host_ri_rt_gw_v.Type = _gw_hop
																case len(i_db_host_ri_rt_gw_v.IF) != 0:
																	gw_i = string(i_db_host_ri_rt_gw_v.IF)
																	i_db_host_ri_rt_gw_v.Type = _gw_interface
																case len(i_db_host_ri_rt_gw_v.Table) != 0:
																	gw_i = i_db_host_ri_rt_gw_v.Table
																	i_db_host_ri_rt_gw_v.Type = _gw_table
																default:
																	continue
																}
															default:
																continue
															}
															i_db_host_ri_rt_gw_o[_GW_Name(gw_i)] = wDB_Host_RI_RT_GW{
																IP:          i_db_host_ri_rt_gw_v.IP,
																IF:          i_db_host_ri_rt_gw_v.IF,
																Table:       i_db_host_ri_rt_gw_v.Table,
																Discard:     i_db_host_ri_rt_gw_v.Discard,
																Type:        i_db_host_ri_rt_gw_v.Type,
																Reserved:    i_db_host_ri_rt_gw_v.Reserved,
																Description: i_db_host_ri_rt_gw_v.Description,
															}
														default:
														}
													}
													return
												}(),
											}
										default:
										}
									}
									return
								}(),
								IF: func() (i_db_host_ri_if_o map[_IF_Name]wDB_Host_RI_IF) {
									i_db_host_ri_if_o = make(map[_IF_Name]wDB_Host_RI_IF)
									for _, i_db_host_ri_if_v := range i_db_host_ri_v.IF {
										switch i_db_host_ri_if_v.Reserved {
										case false:
											switch i_db_host_ri_if_ri, flag := i_db_host_if_ri_v[i_db_host_ri_if_v.Name]; flag {
											case true:
												log.Warnf("peer: '%v', RI: '%v', IF: '%v', already defind in RI: '%v'; ACTION: overwrite.", i_db_host_v.ASN, i_db_host_ri_v.Name, i_db_host_ri_if_v.Name, i_db_host_ri_if_ri)
												delete(i_db_host_ri_if_index_v, i_db_host_ri_if_v.Index)
											}
											i_db_host_ri_if_index_v[func() (i_db_host_ri_if_index_o _IF_Index) {
												switch _, flag := i_db_host_ri_if_index_v[i_db_host_ri_if_v.Index]; flag {
												case false:
													i_db_host_ri_if_index_v[i_db_host_ri_if_v.Index] = i_db_host_ri_if_v.Name
													return i_db_host_ri_if_v.Index
												}
												for {
													switch _, flag := i_db_host_ri_if_index_v[i_db_host_ri_if_index_o]; flag {
													case false:
														i_db_host_ri_if_index_v[i_db_host_ri_if_index_o] = i_db_host_ri_if_v.Name
														return
													}
													i_db_host_ri_if_index_o++
												}
											}()] = i_db_host_ri_if_v.Name
											switch i_db_host_ri_if_v.Communication {
											case _if_comm_ptp, _if_comm_ptmp:
											case "":
												i_db_host_ri_if_v.Communication = _default_if_comm
											default:
												continue
											}
											var (
												i_db_host_ri_if_address_index_v = make(map[_IP_Address_Index]netip.Addr)
											)
											i_db_host_ri_if_o[i_db_host_ri_if_v.Name] = wDB_Host_RI_IF{
												Index:         i_db_host_ri_if_v.Index,
												Communication: i_db_host_ri_if_v.Communication,
												Address: func() (i_db_host_ri_if_address_o map[netip.Addr]wDB_Host_RI_IF_Address) {
													i_db_host_ri_if_address_o = make(map[netip.Addr]wDB_Host_RI_IF_Address)
													for _, i_db_host_ri_if_address_v := range i_db_host_ri_if_v.Address {
														switch i_db_host_ri_if_address_v.Reserved {
														case false:
															i_db_host_ri_if_address_o[i_db_host_ri_if_address_v.IPPrefix.Addr()] = wDB_Host_RI_IF_Address{
																IPPrefix: i_db_host_ri_if_address_v.IPPrefix,
																Index: func() (i_db_host_ri_if_address_index_o _IP_Address_Index) {
																	switch _, flag := i_db_host_ri_if_address_index_v[i_db_host_ri_if_address_v.Index]; flag {
																	case false:
																		i_db_host_ri_if_address_index_v[i_db_host_ri_if_address_v.Index] = i_db_host_ri_if_address_v.IPPrefix.Addr()
																		return i_db_host_ri_if_address_v.Index
																	}
																	for {
																		switch _, flag := i_db_host_ri_if_address_index_v[i_db_host_ri_if_address_index_o]; flag {
																		case false:
																			i_db_host_ri_if_address_index_v[i_db_host_ri_if_address_index_o] = i_db_host_ri_if_address_v.IPPrefix.Addr()
																			return
																		}
																		i_db_host_ri_if_address_index_o++
																	}
																}(),
																NAT:         i_db_host_ri_if_address_v.NAT,
																DHCP:        i_db_host_ri_if_address_v.DHCP,
																Reserved:    i_db_host_ri_if_address_v.Reserved,
																Description: i_db_host_ri_if_address_v.Description,
															}
															add_to_address_book_ipset(true, false, "OUTTER_LIST", i_db_host_ri_if_address_v.IPPrefix.Addr(), i_db_host_ri_if_address_v.NAT)
														default:
														}
													}
													return
												}(),
												Proxy_ARP: func() (i_db_host_ri_if_proxy_arp_o map[netip.Addr]wDB_Host_RI_IF_Proxy_ARP) {
													i_db_host_ri_if_proxy_arp_o = make(map[netip.Addr]wDB_Host_RI_IF_Proxy_ARP)
													for _, i_db_host_ri_if_proxy_arp_v := range i_db_host_ri_if_v.Proxy_ARP {
														switch i_db_host_ri_if_proxy_arp_v.Reserved {
														case false:
															i_db_host_ri_if_proxy_arp_o[i_db_host_ri_if_proxy_arp_v.IPPrefix.Addr()] = wDB_Host_RI_IF_Proxy_ARP{
																IPPrefix:    i_db_host_ri_if_proxy_arp_v.IPPrefix,
																NAT:         i_db_host_ri_if_proxy_arp_v.NAT,
																Reserved:    i_db_host_ri_if_proxy_arp_v.Reserved,
																Description: i_db_host_ri_if_proxy_arp_v.Description,
															}
															add_to_address_book_ipset(true, false, "OUTTER_LIST", i_db_host_ri_if_proxy_arp_v.IPPrefix.Addr(), i_db_host_ri_if_proxy_arp_v.NAT)
														default:
														}
													}
													return
												}(),
												Address_Index: i_db_host_ri_if_address_index_v,
												Disable:       i_db_host_ri_if_v.Disable,
												Reserved:      i_db_host_ri_if_v.Reserved,
												Description:   i_db_host_ri_if_v.Description,
											}
											i_db_host_if_ri_v[i_db_host_ri_if_v.Name] = i_db_host_ri_v.Name
										default:
										}
									}
									return
								}(),
								IF_Index:    i_db_host_ri_if_index_v,
								Reserved:    i_db_host_ri_v.Reserved,
								Description: i_db_host_ri_v.Description,
							}
						default:
						}
					}
					return
				}(),
				IF_RI: i_db_host_if_ri_v,
				Hostname: func() string {
					switch len(i_db_host_v.Hostname) == 0 {
					case true:
						return "as" + i_db_host_as_name_v
					}
					return i_db_host_v.Hostname
				}(),
				Version:      i_db_host_v.Version,
				Major:        i_db_host_major_v,
				IKE_GCM:      i_db_host_ike_gcm_v,
				Manufacturer: i_db_host_v.Manufacturer,
				Model:        i_db_host_v.Model,
				Serial:       i_db_host_v.Serial,
				Config_Patch: sanitize_string(&i_db_host_v.Config_Patch),
				Root: func() (i_db_host_root_o string) {
					switch len(i_db_host_v.Root) < 16 {
					case true:
						i_db_host_root_o = generate_passwd(16)
						log.Warnf("peer: '%v', root cleartext password: '%v'", i_db_host_v.ASN, i_db_host_root_o)
						return
					}
					return i_db_host_v.Root
				}(),
				Reserved:     i_db_host_v.Reserved,
				Description:  i_db_host_v.Description,
				Address_Book: &address_book,
				RM_Index:     &rm_index,
				VI:           map[_VI_Index]*wDB_VI{},
				VI_Left:      map[_VI_Index]*wDB_VI_Peer{},
				VI_Right:     map[_VI_Index]*wDB_VI_Peer{},
			}
		default:
		}
	}
	for _, i_db_vi_v := range xml_db.VI {
		switch i_db_vi_v.Reserved {
		case false:
			switch i_db_vi_v.Type {
			case _vi_ti, _vi_gr, _vi_lt:
			case "":
				i_db_vi_v.Type = _default_vi
			default:
				continue
			}
			switch i_db_vi_v.Communication {
			case _if_comm_ptp, _if_comm_ptmp:
			case "":
				i_db_vi_v.Communication = _default_vi_comm
			default:
				continue
			}
			i_db_vi[i_db_vi_v.Index] = &wDB_VI{
				VI_Index_Padded_Name: _VI_Index_Padded_Name(fmt.Sprintf("%05d", i_db_vi_v.Index)),
				Type:                 i_db_vi_v.Type,
				Communication:        i_db_vi_v.Communication,
				Route_Metric: func() uint {
					switch i_db_vi_v.Route_Metric > _rm_max {
					case true:
						return 0
					}
					return _rm_max - i_db_vi_v.Route_Metric
				}(),
				PSK: func() string {
					switch len(i_db_vi_v.PSK) < 48 {
					case true:
						return generate_passwd(64)
					}
					return i_db_vi_v.PSK
				}(),
				// Peer: func() (i_db_vi_peer_o map[_VI_Peer_Index]*wDB_VI_Peer) {
				// 	i_db_vi_peer_o = make(map[_VI_Peer_Index]*wDB_VI_Peer)
				// 	for _, i_db_vi_peer_v := range i_db_vi_v.Peer {
				// 		switch i_db_vi_peer_v.Reserved {
				// 		case false:
				// 			switch _, flag := i_db_host[i_db_vi_peer_v.ASN]; flag {
				// 			case true:
				// 				i_db_vi_peer_v.RI = parse_RI(&i_db_vi_peer_v.RI)
				// 				switch _, flag := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI]; flag {
				// 				case false:
				// 					continue
				// 				}
				// 				i_db_vi_peer_v.Inner_RI = parse_RI(&i_db_vi_peer_v.Inner_RI)
				// 				switch _, flag := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.Inner_RI]; flag {
				// 				case false:
				// 					continue
				// 				}
				// 				switch i_db_vi_peer_v.IP.IsValid() {
				// 				case true:
				// 					switch _, flag := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address[i_db_vi_peer_v.IP]; flag {
				// 					case false:
				// 						continue
				// 					}
				// 				case false:
				// 					switch len(i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address) != 0 {
				// 					case true:
				// 						var (
				// 							index _IP_Address_Index = 1 >> 1
				// 						)
				// 						for address_index := range i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address_Index {
				// 							switch index > address_index {
				// 							case true:
				// 								index = address_index
				// 							}
				// 						}
				// 						i_db_vi_peer_v.IP = i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address_Index[index]
				// 					}
				// 				}
				// 				switch len(i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address) > 1 {
				// 				case true:
				// 					i_db_vi_peer_v.Local_Address = true
				// 				}
				// 				i_db_vi_peer_o[i_db_vi_peer_v.Index] = &wDB_VI_Peer{
				// 					Index:         i_db_vi_peer_v.Index,
				// 					ASN:           i_db_vi_peer_v.ASN,
				// 					RI:            i_db_vi_peer_v.RI,
				// 					IF:            i_db_vi_peer_v.IF,
				// 					IP:            i_db_vi_peer_v.IP,
				// 					Local_Address: i_db_vi_peer_v.Local_Address,
				// 					Dynamic:       i_db_vi_peer_v.Dynamic,
				// 					Hub:           i_db_vi_peer_v.Hub,
				// 					Inner_RI:      i_db_vi_peer_v.Inner_RI,
				// 					Reserved:      i_db_vi_peer_v.Reserved,
				// 					Description:   i_db_vi_peer_v.Description,
				// 					Verbosity:     i_db_vi_peer_v.Verbosity,
				// 				}
				// 			default:
				// 				continue
				// 			}
				// 		default:
				// 		}
				// 	}
				// 	return
				// }(),
				Peer_AS_Index: map[_VI_Peer_Index]_AS_Number{},
				IPPrefix:      get_vi_ipprefix(i_db_vi_v.Index, 0),
				Reserved:      i_db_vi_v.Reserved,
				Description:   i_db_vi_v.Description,
			}
			i_db_vi_peer[i_db_vi_v.Index] = func() (i_db_vi_peer_o map[_VI_Peer_Index]*wDB_VI_Peer) {
				i_db_vi_peer_o = make(map[_VI_Peer_Index]*wDB_VI_Peer)
				for _, i_db_vi_peer_v := range i_db_vi_v.Peer {
					switch i_db_vi_peer_v.Reserved {
					case false:
						switch _, flag := i_db_host[i_db_vi_peer_v.ASN]; flag {
						case true:
							i_db_vi_peer_v.RI = parse_RI(&i_db_vi_peer_v.RI)
							switch _, flag := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI]; flag {
							case false:
								continue
							}
							i_db_vi_peer_v.Inner_RI = parse_RI(&i_db_vi_peer_v.Inner_RI)
							switch _, flag := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.Inner_RI]; flag {
							case false:
								continue
							}
							switch i_db_vi_peer_v.IP.IsValid() {
							case true:
								switch _, flag := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address[i_db_vi_peer_v.IP]; flag {
								case false:
									continue
								}
							case false:
								switch len(i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address) != 0 {
								case true:
									var (
										index _IP_Address_Index = 1 >> 1
									)
									for address_index := range i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address_Index {
										switch index > address_index {
										case true:
											index = address_index
										}
									}
									i_db_vi_peer_v.IP = i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address_Index[index]
								}
							}
							switch len(i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address) > 1 {
							case true:
								i_db_vi_peer_v.Local_Address = true
							}
							var (
								i_db_vi_peer_nat_v     netip.Addr
								i_db_vi_peer_use_nat_v bool
							)
							switch i_db_vi_peer_nat_i := i_db_host[i_db_vi_peer_v.ASN].RI[i_db_vi_peer_v.RI].IF[i_db_vi_peer_v.IF].Address[i_db_vi_peer_v.IP].NAT; i_db_vi_peer_nat_i.IsValid() {
							case true:
								i_db_vi_peer_nat_v = i_db_vi_peer_nat_i
								i_db_vi_peer_use_nat_v = true
							}
							i_db_vi_peer_o[i_db_vi_peer_v.Index] = &wDB_VI_Peer{
								Index:          i_db_vi_peer_v.Index,
								ASN:            i_db_vi_peer_v.ASN,
								RI:             i_db_vi_peer_v.RI,
								IF:             i_db_vi_peer_v.IF,
								IP:             i_db_vi_peer_v.IP,
								NAT:            i_db_vi_peer_nat_v,
								Use_NAT:        i_db_vi_peer_use_nat_v,
								Local_Address:  i_db_vi_peer_v.Local_Address,
								Dynamic:        i_db_vi_peer_v.Dynamic,
								No_NAT:         true,
								Hub:            i_db_vi_peer_v.Hub,
								Inner_RI:       i_db_vi_peer_v.Inner_RI,
								Inner_IPPrefix: get_vi_ipprefix(i_db_vi_v.Index, 1+i_db_vi_peer_v.Index),
								Reserved:       i_db_vi_peer_v.Reserved,
								Description:    i_db_vi_peer_v.Description,
							}
							i_db_vi[i_db_vi_v.Index].Peer_AS_Index[i_db_vi_peer_v.Index] = i_db_vi_peer_v.ASN
						default:
							continue
						}
					default:
					}
				}
				return
			}()
		default:
		}
	}
	for i_db_vi_i, i_db_vi_peers_v := range i_db_vi_peer {
		for i_db_vi_peer_i, i_db_vi_peer_v := range i_db_vi_peers_v {
			i_db_host[i_db_vi_peer_v.ASN].VI[i_db_vi_i] = i_db_vi[i_db_vi_i]
			i_db_host[i_db_vi_peer_v.ASN].VI_Left[i_db_vi_i] = i_db_vi_peer_v
			for index, value := range i_db_vi[i_db_vi_i].Peer_AS_Index {
				switch i_db_vi_peer_i != index {
				case true:
					i_db_host[value].VI_Right[i_db_vi_i] = i_db_vi_peer_v
				}
			}
		}
	}
	for _, i_db_template_v := range xml_db.Template {
		switch i_db_template_v.Reserved {
		case false:
			switch _, flag := i_db_template[i_db_template_v.Name]; flag {
			case false:
				i_db_template[i_db_template_v.Name] = &wDB_Template{
					Content:     sanitize_string(&i_db_template_v.Content),
					Reserved:    i_db_template_v.Reserved,
					Description: i_db_template_v.Description,
				}
			default:
				log.Warnf("template '%v' already exist; ACTION: skip.", i_db_template_v.Name)
			}
		default:
		}
	}
	log.Infof("'%+v'", i_db_host)
	return
}
func main() {
	switch err := read_db(); err != nil {
	case true:
		log.Fatalf("DB read error: '%v'", err)
		return
	}
	switch err := use_db(); err != nil {
	case true:
		log.Fatalf("DB use error: '%v'", err)
		return
	}
	// log.Infof("'%+v''%+v''%+v'", i_db_template, i_db_host, i_db_vi)
	// log.Infof("'%+v'", i_db_template)
	// log.Infof("'%+v'", i_db_host)
	// log.Infof("'%+v'", i_db_vi)
	// log.Infof("'%+v'", generate_passwd(16))
	// log.Infof("'%+v'", hpow7)
	log.Infof("'%s'", config[4200240063])
	// log.Infof("'%+v'", address_book_ipset["OUTTER_LIST"].Prefixes())
	// a := address_book_ipset["OUTTER_LIST"].Prefixes()
	// log.Infof("'%+v'", i_db_vi_peer[63][0])
	// log.Infof("'%+v'", i_db_vi_peer[63][1])
	// log.Infof("'%+v'", i_db_host[4200240063].VI[197])
	// log.Infof("'%+v'", i_db_host[4200240063].VI_Left[197])
	// log.Infof("'%+v'", i_db_host[4200240063].VI_Right[197])
	// log.Infof("'%+v'", i_db_host[4200240005].VI[69])
	// log.Infof("'%+v'", i_db_host[4200240005].VI_Left[69])
	// log.Infof("'%+v'", i_db_host[4200240005].VI_Right[69])
}
func use_db() (err error) {
	for key, value := range i_db_host {
		var (
			i_template *template.Template
			buf        bytes.Buffer
		)
		switch i_template, err = template.New("asXXXXXXXXXX").Funcs(template_FuncMap).Parse(i_db_template["asXXXXXXXXXX"].Content); err == nil && i_template != nil {
		case true:
			switch err = i_template.Execute(&buf, value); err == nil && i_template != nil {
			case true:
				config[key] = buf
			default:
				return
			}
		default:
			return
		}
	}
	return
}

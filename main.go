package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
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
// TODO: this program is just an adapter written in golang for the gotemplate defined in the config

type _ID [_hash_Size]uint8 // _ID here is a result of sha3.Sum512.

type _AB map[string]map[netip.Prefix]bool
type _ASN uint32
type _ASN_PName uint32
type _GW_Name string
type _GW_Type string
type _IF_Communication string
type _IF_ID uint
type _IF_Name string
type _IP_ID uint
type _RI_Name string
type _RM_ID [_rm_max + 1]uint32
type _GT_Content string
type _GT_Name string
type _VI_ID uint
type _VI_ID_PName string
type _VI_Peer_ID uint
type _VI_Type string

type sDB struct {
	XMLName     xml.Name     `xml:"AS4200240XXX"`
	Peer        []sDB_Peer   `xml:"peer_list>peer"`
	VI          []sDB_VI     `xml:"VI_list>VI"`
	GT          []sDB_GT     `xml:"template_list>GT"`
	VI_IPPrefix netip.Prefix `xml:"VI_IPPrefix,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description string       `xml:"description,attr"`
	Verbosity   string       `xml:"verbosity,attr"`
}
type sDB_GT struct {
	Name        _GT_Name `xml:"name,attr"`
	Content     string   `xml:",chardata"`
	Reserved    bool     `xml:"reserved,attr"`
	Description string   `xml:"description,attr"`
}
type sDB_Peer struct {
	ASN          _ASN          `xml:"ASN,attr"`
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
	Name          _IF_Name                 `xml:"name,attr"`
	ID            _IF_ID                   `xml:"index,attr"`
	Communication _IF_Communication        `xml:"communication,attr"`
	IP            []sDB_Peer_RI_IF_Address `xml:"IP"`
	PARP          []sDB_Peer_RI_IF_PARP    `xml:"PARP"`
	Disable       bool                     `xml:"disable,attr"`
	Reserved      bool                     `xml:"reserved,attr"`
	Description   string                   `xml:"description,attr"`
}
type sDB_Peer_RI_IF_Address struct {
	ID          _IP_ID       `xml:"index,attr"`
	IPPrefix    netip.Prefix `xml:"ipprefix,attr"`
	NAT         netip.Addr   `xml:"NAT,attr"`
	DHCP        bool         `xml:"dhcp,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description string       `xml:"description,attr"`
}
type sDB_Peer_RI_IF_PARP struct {
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
	ID            _VI_ID            `xml:"index,attr"`
	Type          _VI_Type          `xml:"type,attr"`
	Communication _IF_Communication `xml:"communication,attr"`
	Route_Metric  uint              `xml:"route_metric,attr"`
	Peer          []sDB_VI_Peer     `xml:"peer"`
	PSK           string            `xml:"PSK,attr"`
	Reserved      bool              `xml:"reserved,attr"`
	Description   string            `xml:"description,attr"`
}
type sDB_VI_Peer struct {
	ID            _VI_Peer_ID `xml:"index,attr"`
	ASN           _ASN        `xml:"ASN,attr"`
	RI            _RI_Name    `xml:"RI,attr"`
	IF            _IF_Name    `xml:"IF,attr"`
	IP            netip.Addr  `xml:"IP,attr"`
	Local_Address bool        `xml:"local_address,attr"`
	Dynamic       bool        `xml:"dynamic,attr"`
	No_NAT        bool        `xml:"no_nat,attr"`
	Hub           bool        `xml:"hub,attr"`
	Inner_RI      _RI_Name    `xml:"inner_RI,attr"`
	Reserved      bool        `xml:"reserved,attr"`
	Description   string      `xml:"description,attr"`
}

type pDB_peer struct {
	ASN          _ASN
	ASN_PName    _ASN_PName
	Router_ID    netip.Addr
	RI           map[_RI_Name]pDB_Peer_RI
	IF_RI        map[_IF_Name]_RI_Name
	Hostname     string
	Version      string
	Major        float64
	IKE_GCM      bool
	Manufacturer string
	Model        string
	Serial       string
	Config_Patch string
	Root         string
	Reserved     bool
	Description  string
	VI           map[_VI_ID]pDB_Peer_VI
	RM_ID        *_RM_ID
	AB           *_AB
}
type pDB_Peer_RI struct {
	RT          map[netip.Prefix]pDB_Peer_RI_RT
	IF          map[_IF_Name]pDB_Peer_RI_IF
	Reserved    bool
	Description string
}
type pDB_Peer_RI_RT struct {
	GW          map[_GW_Name]pDB_Peer_RI_RT_GW
	Reserved    bool
	Description string
}
type pDB_Peer_RI_RT_GW struct {
	IP          netip.Addr // name candidate priority 1
	IF          _IF_Name   // name candidate priority 2
	Table       string     // name candidate priority 3
	Discard     bool       // name candidate priority 0
	Type        _GW_Type   // fill type appropriately
	Metric      uint
	Reserved    bool
	Description string
}
type pDB_Peer_RI_IF struct {
	ID            _IF_ID
	Communication _IF_Communication
	IP            map[netip.Addr]pDB_Peer_RI_IF_IP
	PARP          map[netip.Addr]pDB_Peer_RI_IF_PARP
	Disable       bool
	Reserved      bool
	Description   string
}
type pDB_Peer_RI_IF_IP struct {
	ID          _IP_ID
	IPPrefix    netip.Prefix
	NAT         netip.Addr
	DHCP        bool
	Reserved    bool
	Description string
}
type pDB_Peer_RI_IF_PARP struct {
	IPPrefix    netip.Prefix
	NAT         netip.Addr
	Reserved    bool
	Description string
}
type pDB_Peer_VI struct {
	VI_ID_PName          _VI_ID_PName
	Type                 _VI_Type
	Communication        _IF_Communication
	PSK                  string
	Route_Metric         uint
	IPPrefix             netip.Prefix
	No_NAT               bool
	Left_ASN             _ASN
	Left_RI              _RI_Name
	Left_IF              _IF_Name
	Left_IP              netip.Addr
	Left_NAT             netip.Addr
	Left_Local_Address   bool
	Left_Dynamic         bool
	Left_Hub             bool
	Left_Inner_RI        _RI_Name
	Left_Inner_IPPrefix  netip.Prefix
	Right_ASN            _ASN
	Right_RI             _RI_Name
	Right_IF             _IF_Name
	Right_IP             netip.Addr
	Right_NAT            netip.Addr
	Right_Local_Address  bool
	Right_Dynamic        bool
	Right_Hub            bool
	Right_Inner_RI       _RI_Name
	Right_Inner_IPPrefix netip.Prefix
	Reserved             bool
	Description          string
}
type pDB_VI struct {
	VI_ID_PName   _VI_ID_PName
	Type          _VI_Type
	Communication _IF_Communication
	PSK           string
	Route_Metric  uint
	Peer          map[_VI_Peer_ID]pDB_VI_Peer
	Peer_AS_ID    map[_VI_Peer_ID]_ASN
	IPPrefix      netip.Prefix
	No_NAT        bool
	Reserved      bool
	Description   string
}
type pDB_VI_Peer struct {
	ID             _VI_Peer_ID
	ASN            _ASN
	RI             _RI_Name
	IF             _IF_Name
	IP             netip.Addr
	NAT            netip.Addr
	Local_Address  bool
	Dynamic        bool
	Hub            bool
	Inner_RI       _RI_Name
	Inner_IPPrefix netip.Prefix
	Reserved       bool
	Description    string
}
type pDB_GT struct {
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
	_juniper_mgmt_IF     _IF_Name          = "lo0.0"
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
	hash_cache sync.Map
	re_caps    = regexp.MustCompile(`[A-Z]`)
	gt_fm      = template.FuncMap{"sum_uint32": sum_uint32_gt_fm}
	_loglevel  = _default_loglevel
	rm_id      = func() (outbound _RM_ID) {
		for shift, interim := 0, 0; interim <= int(_rm_max); interim, shift = interim+1, shift+int(_rm_bits) {
			outbound[interim] = 1 << shift
		}
		return
	}()
	ab          = make(_AB)
	vi_ipprefix netip.Prefix
	vi_ip_shift _VI_ID
	pdb_peer    = make(map[_ASN]pDB_peer)
	pdb_vi      = make(map[_VI_ID]pDB_VI)
	pdb_gt      = make(map[_GT_Name]pDB_GT)
	config      = make(map[_ASN]bytes.Buffer) // resulting configs
	// i_db_host     = make(map[_ASN]*wDB_Host)                      // Peer_ASN
	// i_db_vi       = make(map[_VI_ID]*wDB_VI)                      // VI_ID
	// i_db_vi_peer  = make(map[_VI_ID]map[_VI_Peer_ID]*wDB_VI_Peer) // VI_Peer_ID
	// i_db_template = make(map[_GT_Name]*wDB_GT)                    // GT_Name
)

func (inbound _ASN) String() (outbound string) {
	outbound = "0000000000" + strconv.FormatUint(uint64(inbound), 10)
	return outbound[len(outbound)-10:]
}
func (inbound _VI_ID) String() (outbound string) {
	outbound = "00000" + strconv.FormatUint(uint64(inbound), 10)
	return outbound[len(outbound)-5:]
}
func get_vi_ipprefix(vi_shift _VI_ID, peer_shift _VI_Peer_ID) (outbound netip.Prefix) {
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
	vi_ip_shift = _VI_ID(binary.BigEndian.Uint32(vi_ipprefix.Addr().AsSlice()))
}
func sum_uint32_gt_fm(inbound ...uint32) (outbound uint32) {
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
func add_to_ab_ipset(public, private bool, ab_name string, ip ...interface{}) {
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
		switch _, flag := ab[ab_name]; flag {
		case false:
			// ab[ab_name] = make(map[netip.Prefix]bool)
			ab[ab_name] = map[netip.Prefix]bool{
				interim: true,
			}
			continue
		}
		switch _, flag := ab[ab_name][interim]; flag {
		case false:
			ab[ab_name][interim] = true
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

	for _, value := range xml_db.Peer {

	}
	for _, value := range xml_db.GT {
		switch value.Reserved {
		case false:
			switch _, flag := pdb_gt[value.Name]; flag {
			case false:
				pdb_gt[value.Name] = pDB_GT{
					Content:     sanitize_string(&value.Content),
					Reserved:    value.Reserved,
					Description: value.Description,
				}
			default:
				log.Warnf("template '%v' already exist; ACTION: skip.", value.Name)
			}
		default:
		}
	}
	log.Infof("'%+v'", pdb_gt)
	return
}
func use_db() (err error) {
	for key, value := range pdb_peer {
		switch value.Reserved {
		case false:
			var (
				gt  *template.Template
				buf bytes.Buffer
			)
			switch gt, err = template.New("asXXXXXXXXXX").Funcs(gt_fm).Parse(pdb_gt["asXXXXXXXXXX"].Content); err == nil && gt != nil {
			case true:
				switch err = gt.Execute(&buf, value); err == nil && gt != nil {
				case true:
					config[key] = buf
				default:
					return
				}
			default:
				return
			}
		}
	}
	return
}

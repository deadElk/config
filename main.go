/* // go:generate stringer -type=_ASN */

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
type _ASN_PName string
type _GW_Name string
type _GW_Type string
type _IF_Communication string
type _IF_Mode string
type _IF_Name string
type _RI_Name string
type _RM_ID [_rm_max + 1]uint32
type _GT_Content string
type _GT_Name string
type _VI_ID uint
type _VI_ID_PName string
type _VI_Peer_ID uint
type _VI_Type string
type _Description string
type _Policy string
type _Secret string

type sDB struct {
	XMLName     xml.Name     `xml:"AS4200240XXX"`
	Peer        []sDB_Peer   `xml:"peer_list>peer"`
	VI          []sDB_VI     `xml:"VI_list>VI"`
	GT          []sDB_GT     `xml:"template_list>GT"`
	VI_IPPrefix netip.Prefix `xml:"VI_IPPrefix,attr"`
	GT_List     string       `xml:"GT_list,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
	Verbosity   string       `xml:"verbosity,attr"`
}
type sDB_GT struct {
	Name        _GT_Name     `xml:"name,attr"`
	Content     _GT_Content  `xml:",chardata"`
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
}
type sDB_Peer struct {
	ASN          _ASN          `xml:"ASN,attr"`
	RI           []sDB_Peer_RI `xml:"RI"`
	Hostname     string        `xml:"hostname,attr"`
	Version      string        `xml:"version,attr"`
	Manufacturer string        `xml:"manufacturer,attr"`
	Model        string        `xml:"model,attr"`
	Serial       string        `xml:"serial,attr"`
	GT_Patch     _GT_Content   `xml:"GT_patch"`
	Root         _Secret       `xml:"root,attr"`
	GT_List      string        `xml:"GT_list,attr"`
	Reserved     bool          `xml:"reserved,attr"`
	Description  _Description  `xml:"description,attr"`
}
type sDB_Peer_RI struct {
	Name        _RI_Name         `xml:"name,attr"`
	RT          []sDB_Peer_RI_RT `xml:"RT"`
	IF          []sDB_Peer_RI_IF `xml:"IF"`
	Policy      _Policy          `xml:"policy,attr"`
	Reserved    bool             `xml:"reserved,attr"`
	Description _Description     `xml:"description,attr"`
}
type sDB_Peer_RI_IF struct {
	Name          _IF_Name                 `xml:"name,attr"`
	Communication _IF_Communication        `xml:"communication,attr"`
	IP            []sDB_Peer_RI_IF_Address `xml:"IP"`
	PARP          []sDB_Peer_RI_IF_PARP    `xml:"PARP"`
	Disable       bool                     `xml:"disable,attr"`
	Reserved      bool                     `xml:"reserved,attr"`
	Description   _Description             `xml:"description,attr"`
}
type sDB_Peer_RI_IF_Address struct {
	IPPrefix    netip.Prefix `xml:"ipprefix,attr"`
	Router_ID   bool         `xml:"router_id,attr"`
	Primary     bool         `xml:"primary,attr"`
	Preferred   bool         `xml:"preferred,attr"`
	NAT         netip.Addr   `xml:"NAT,attr"`
	DHCP        bool         `xml:"dhcp,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
}
type sDB_Peer_RI_IF_PARP struct {
	IPPrefix    netip.Prefix `xml:"ipprefix,attr"`
	NAT         netip.Addr   `xml:"NAT,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
}
type sDB_Peer_RI_RT struct {
	Identifier  netip.Prefix        `xml:"identifier,attr"`
	GW          []sDB_Peer_RI_RT_GW `xml:"GW"`
	Reserved    bool                `xml:"reserved,attr"`
	Description _Description        `xml:"description,attr"`
}
type sDB_Peer_RI_RT_GW struct {
	IP          netip.Addr   `xml:"ip,attr"`
	IF          _IF_Name     `xml:"IF,attr"`
	Table       string       `xml:"table,attr"`
	Discard     bool         `xml:"discard,attr"`
	Type        _GW_Type     `xml:"type,attr"`
	Metric      uint         `xml:"metric,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
}
type sDB_VI struct {
	ID            _VI_ID            `xml:"index,attr"`
	Type          _VI_Type          `xml:"type,attr"`
	Communication _IF_Communication `xml:"communication,attr"`
	Route_Metric  uint              `xml:"route_metric,attr"`
	Peer          []sDB_VI_Peer     `xml:"peer"`
	PSK           _Secret           `xml:"PSK,attr"`
	Reserved      bool              `xml:"reserved,attr"`
	Description   _Description      `xml:"description,attr"`
}
type sDB_VI_Peer struct {
	ID          _VI_Peer_ID  `xml:"index,attr"`
	ASN         _ASN         `xml:"ASN,attr"`
	RI          _RI_Name     `xml:"RI,attr"`
	IF          _IF_Name     `xml:"IF,attr"`
	IP          netip.Addr   `xml:"IP,attr"`
	Dynamic     bool         `xml:"dynamic,attr"`
	Hub         bool         `xml:"hub,attr"`
	Inner_RI    _RI_Name     `xml:"inner_RI,attr"`
	Reserved    bool         `xml:"reserved,attr"`
	Description _Description `xml:"description,attr"`
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
	GT_Patch     _GT_Content
	Root         _Secret
	GT_List      []_GT_Name
	Reserved     bool
	Description  _Description
	VI           map[_VI_ID]pDB_Peer_VI
	RM_ID        *_RM_ID
	AB           *_AB
}
type pDB_Peer_RI struct {
	RT          map[netip.Prefix]pDB_Peer_RI_RT
	IF          map[_IF_Name]pDB_Peer_RI_IF
	IP_IF       map[netip.Addr]_IF_Name
	Policy      _Policy
	Reserved    bool
	Description _Description
}
type pDB_Peer_RI_RT struct {
	GW          map[_GW_Name]pDB_Peer_RI_RT_GW
	Reserved    bool
	Description _Description
}
type pDB_Peer_RI_RT_GW struct {
	IP          netip.Addr // name candidate priority 1
	IF          _IF_Name   // name candidate priority 2
	Table       string     // name candidate priority 3
	Discard     bool       // name candidate priority 0
	Type        _GW_Type   // fill type appropriately
	Metric      uint
	Reserved    bool
	Description _Description
}
type pDB_Peer_RI_IF struct {
	Communication _IF_Communication
	Major         string
	Minor         string
	IP            map[netip.Addr]pDB_Peer_RI_IF_IP
	PARP          map[netip.Addr]pDB_Peer_RI_IF_PARP
	Disable       bool
	Reserved      bool
	Description   _Description
}
type pDB_Peer_RI_IF_IP struct {
	IPPrefix    netip.Prefix
	Masked      netip.Prefix
	Router_ID   bool
	Primary     bool
	Preferred   bool
	NAT         netip.Addr
	DHCP        bool
	Reserved    bool
	Description _Description
}
type pDB_Peer_RI_IF_PARP struct {
	IPPrefix    netip.Prefix
	NAT         netip.Addr
	Reserved    bool
	Description _Description
}
type pDB_Peer_VI struct {
	VI_ID_PName          _VI_ID_PName
	Type                 _VI_Type
	Communication        _IF_Communication
	PSK                  _Secret
	Route_Metric         uint
	IPPrefix             netip.Prefix
	No_NAT               bool
	IKE_GCM              bool
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
	Description          _Description
}
type pDB_GT struct {
	Content     _GT_Content
	Reserved    bool
	Description _Description
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
	_juniper_mgmt_RI     _RI_Name          = "mgmt_junos"
	_juniper_mgmt_IF     _IF_Name          = "fxp0.0"
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
	_if_mode_vi          _IF_Mode          = "vi"
	_if_mode_link        _IF_Mode          = "link"
	_node0               string            = "node0"
	_node1               string            = "node1"
	_rm_bits             uint              = 2
	_rm_max                                = 32/_rm_bits - 1
	_policy_restrictive  _Policy           = "restrictive"
	_policy_permissive   _Policy           = "permissive"
	_default_policy                        = _policy_permissive
)

var (
	hash_cache sync.Map
	re_caps    = regexp.MustCompile(`[A-Z]`)
	re_dot     = regexp.MustCompile(`\.`)
	re_period  = regexp.MustCompile(`,`)
	gt_fm      = template.FuncMap{
		"sum_uint32": sum_uint32_gt_fm,
		"sum_string": sum_string_gt_fm,
	}
	_loglevel = _default_loglevel
	rm_id     = func() (outbound _RM_ID) {
		for shift, interim := 0, 0; interim <= int(_rm_max); interim, shift = interim+1, shift+int(_rm_bits) {
			outbound[interim] = 1 << shift
		}
		return
	}()
	ab          = make(_AB)
	vi_ipprefix netip.Prefix
	vi_ip_shift _VI_ID
	pdb_peer    = make(map[_ASN]pDB_peer)
	pdb_gt      = make(map[_GT_Name]pDB_GT)
	config      = make(map[_ASN][]bytes.Buffer)
)

func (inbound _ASN) String() (outbound string) {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _ASN) Parse() _ASN_PName {
	var (
		interim = "0000000000" + strconv.FormatUint(uint64(inbound), 10)
	)
	return _ASN_PName(interim[len(interim)-10:])
}
func (inbound _ASN_PName) String() (outbound string) {
	return string(inbound)
}
func (inbound _VI_ID) Parse() (outbound _VI_ID_PName) {
	var (
		interim = "00000" + strconv.FormatUint(uint64(inbound), 10)
	)
	return _VI_ID_PName(interim[len(interim)-5:])
}
func (inbound _VI_ID) String() string {
	return strconv.FormatUint(uint64(inbound), 10)
}
func (inbound _VI_ID_PName) String() (outbound string) {
	return string(inbound)
}
func (inbound _IF_Communication) Parse(mode _IF_Mode) (outbound _IF_Communication) {
	switch mode {
	case _if_mode_vi:
		switch inbound {
		case _if_comm_ptmp, _if_comm_ptp:
			return inbound
		case "":
			return _default_vi_comm
		default:
			outbound = _default_vi_comm
		}
	case _if_mode_link:
		switch inbound {
		case _if_comm_ptmp, _if_comm_ptp:
			return inbound
		case "":
			return _default_if_comm
		default:
			outbound = _default_if_comm
		}
	}
	log.Warnf("unknow IF Communication type '%v'; ACTION: use '%v'.", inbound, outbound)
	return
}
func (inbound _Description) Parse(default_description _Description) _Description {
	switch len(inbound) == 0 {
	case true:
		return default_description
	}
	return inbound
}
func (inbound _GT_Content) Sanitize() (outbound _GT_Content) {
	for _, value := range strings.Split(string(inbound), "\n") {
		outbound += _GT_Content(strings.TrimSpace(value) + "\n")
	}
	return
}
func (inbound _RI_Name) String() string {
	return string(inbound)
}
func (inbound _RI_Name) Parse() _RI_Name {
	switch len(inbound) == 0 {
	case true:
		return _juniper_default_RI
	}
	return inbound
}
func (inbound _IF_Name) String() string {
	return string(inbound)
}
func (inbound _GW_Type) String() string {
	return string(inbound)
}
func (inbound _GT_Name) String() string {
	return string(inbound)
}
func (inbound _GT_Content) String() string {
	return string(inbound)
}
func (inbound _Policy) Parse() _Policy {
	switch len(inbound) == 0 || (inbound != _policy_permissive && inbound != _policy_restrictive) {
	case true:
		return _default_policy
	}
	return inbound
}
func (inbound _Policy) String() string {
	return string(inbound)
}
func (inbound _Secret) Parse(length uint, format ...string) _Secret {
	switch len(inbound) >= int(length) {
	case true:
		return inbound
	}
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
	switch len(format) > 0 {
	case true:
		log.Warnf("%v; ACTION: new value is '%v'.", format[0], string(ret))
	}
	return _Secret(ret)
}
func (inbound _Secret) String() string {
	return string(inbound)
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
func sum_string_gt_fm(inbound ...interface{}) (outbound string) {
	switch len(inbound) {
	case 0:
		return
	}
	for _, value := range inbound {
		switch element := value.(type) {
		case string:
			outbound += element
		case _RI_Name:
			outbound += element.String()
		}
	}
	return
}
func add_to_ab(public, private bool, ab_name string, ip ...interface{}) {
	for _, address := range ip {
		var (
			interim netip.Prefix
			bits    = 32
		)
		switch value := (address).(type) {
		case netip.Addr:
			switch is_private, is_valid := value.IsPrivate(), value.IsValid(); !is_valid || (is_private && !private) || (!is_private && !public) {
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
		case string:
			continue
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

	log.Infof("'%s'", config[4200240001])
	// log.Infof("'%+v'", pdb_vi)
	// log.Infof("'%+v'", pdb_peer)
	// log.Infof("'%+v'", pdb_gt)
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
					log.Warnf("configuration file '%v' DB parse error: '%v'; ACTION: skip.", value, err)
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

	for _, value := range xml_db.GT {
		switch _, flag := pdb_gt[value.Name]; flag {
		case true:
			log.Warnf("template '%v' already exist; ACTION: skip.", value.Name)
			continue
		}

		pdb_gt[value.Name] = pDB_GT{
			Content:     value.Content.Sanitize(),
			Reserved:    value.Reserved,
			Description: value.Description,
		}
	}

	for _, value := range xml_db.Peer {
		switch _, flag := pdb_peer[value.ASN]; flag {
		case true:
			log.Warnf("peer ASN '%v' already exist; ACTION: skip.", value.ASN)
			continue
		}
		var (
			vASN_PName = value.ASN.Parse()
			vHostname  = func() (outbound string) {
				switch len(value.Hostname) == 0 {
				case true:
					outbound = "gw_as" + vASN_PName.String()
					log.Warnf("peer ASN '%v' hostname not defined; ACTION: use '%v'.", value.ASN, outbound)
					return
				}
				return value.Hostname
			}()
			vGT_List = func() (outbound []_GT_Name) {
				var (
					interim string
				)
				switch len(value.GT_List) != 0 {
				case false:
					interim = xml_db.GT_List
				default:
					interim = value.GT_List
				}
				var (
					list = re_period.Split(interim, -1)
				)
				for _, list_v := range list {
					switch _, flag := pdb_gt[_GT_Name(list_v)]; flag {
					case true:
						switch pdb_gt[_GT_Name(list_v)].Reserved {
						case false:
							outbound = append(outbound, _GT_Name(list_v))
						default:
							log.Warnf("peer ASN '%v' reserved template '%v' cannot be used; ACTION: skip.", value.ASN, list_v)
							continue
						}
					default:
						log.Warnf("peer ASN '%v', template '%v' not found; ACTION: skip.", value.ASN, list_v)
						continue
					}
				}
				return
			}()
			vMajor = func() float64 {
				var (
					interim = re_caps.Split(value.Version, -1)
				)
				return parse_interface(strconv.ParseFloat(interim[0], 64)).(float64)
			}()
			vRouter_ID netip.Addr
			vIF_RI     = make(map[_IF_Name]_RI_Name)
			vRI        = func() (outbound map[_RI_Name]pDB_Peer_RI) {
				var (
					vIP_IF = make(map[netip.Addr]_IF_Name)
				)
				outbound = make(map[_RI_Name]pDB_Peer_RI)
				for _, ri_v := range value.RI {
					outbound[ri_v.Name] = pDB_Peer_RI{
						RT: func() (rt_o map[netip.Prefix]pDB_Peer_RI_RT) {
							rt_o = make(map[netip.Prefix]pDB_Peer_RI_RT)
							for _, rt_v := range ri_v.RT {
								switch _, flag := rt_o[rt_v.Identifier]; flag {
								case true:
									log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v' already defined; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier)
									continue
								}
								rt_o[rt_v.Identifier] = pDB_Peer_RI_RT{
									GW: func() (gw_o map[_GW_Name]pDB_Peer_RI_RT_GW) {
										gw_o = make(map[_GW_Name]pDB_Peer_RI_RT_GW)
										for _, gw_v := range rt_v.GW {
											var (
												gw_i = strconv.FormatUint(uint64(gw_v.Metric), 10) + "_"
											)
											switch {
											case gw_v.Type == _gw_discard:
												gw_i += _gw_discard.String()
											case gw_v.Type == _gw_hop && gw_v.IP.IsValid():
												gw_i += gw_v.IP.String()
											case gw_v.Type == _gw_interface && len(gw_v.IF) != 0:
												gw_i += gw_v.IF.String()
											case gw_v.Type == _gw_table && len(gw_v.Table) != 0:
												gw_i += gw_v.Table
											case len(gw_v.Type) == 0:
												switch {
												case gw_v.Discard:
													gw_i += _gw_discard.String()
													gw_v.Type = _gw_discard
												case gw_v.IP.IsValid():
													gw_i += gw_v.IP.String()
													gw_v.Type = _gw_hop
												case len(gw_v.IF) != 0:
													gw_i += gw_v.IF.String()
													gw_v.Type = _gw_interface
												case len(gw_v.Table) != 0:
													gw_i += gw_v.Table
													gw_v.Type = _gw_table
												default:
													log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', no gateway found; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier)
													continue
												}
											default:
												log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', unknown gateway type '%v'; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier, gw_v.Type)
												continue
											}
											switch _, flag := gw_o[_GW_Name(gw_i)]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', route Identifier '%v', gateway '%v' already defined; ACTION: skip.", value.ASN, ri_v.Name, rt_v.Identifier, gw_i)
												continue
											}
											gw_o[_GW_Name(gw_i)] = pDB_Peer_RI_RT_GW{
												IP:          gw_v.IP,
												IF:          gw_v.IF,
												Table:       gw_v.Table,
												Discard:     gw_v.Discard,
												Type:        gw_v.Type,
												Metric:      gw_v.Metric,
												Reserved:    gw_v.Reserved,
												Description: gw_v.Description,
											}
										}
										return
									}(),
									Reserved:    rt_v.Reserved,
									Description: rt_v.Description,
								}
							}
							return
						}(),
						IF: func() (if_o map[_IF_Name]pDB_Peer_RI_IF) {
							if_o = make(map[_IF_Name]pDB_Peer_RI_IF)
							for _, if_v := range ri_v.IF {
								switch if_ri_v, flag := vIF_RI[if_v.Name]; flag {
								case true:
									log.Warnf("peer ASN '%v', RI '%v', IF '%v' already defined in RI '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, if_ri_v)
									continue
								}
								vIF_RI[if_v.Name] = ri_v.Name
								var (
									if_o_Major string
									if_o_Minor string
								)
								func() {
									var (
										interim = re_dot.Split(if_v.Name.String(), -1)
									)
									if_o_Major = interim[0]
									if_o_Minor = interim[1]
								}()
								if_o[if_v.Name] = pDB_Peer_RI_IF{
									Communication: if_v.Communication.Parse(_if_mode_link),
									Major:         if_o_Major,
									Minor:         if_o_Minor,
									IP: func() (ip_o map[netip.Addr]pDB_Peer_RI_IF_IP) {
										ip_o = make(map[netip.Addr]pDB_Peer_RI_IF_IP)
										for _, ip_v := range if_v.IP {
											var (
												ip_i = ip_v.IPPrefix.Addr()
											)
											switch ip_if_v, flag := vIP_IF[ip_i]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', IF '%v', IP '%v' already defined in IF '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, ip_i, ip_if_v)
												continue
											}
											vIP_IF[ip_i] = if_v.Name
											switch ip_v.Router_ID {
											case true:
												switch vRouter_ID.IsValid() {
												case false:
													vRouter_ID = ip_i
												default:
													log.Warnf("peer ASN '%v', router ID '%v' already defined; ACTION: skip.", value.ASN, vRouter_ID)
												}
											}
											add_to_ab(true, false, "OUTTER_LIST", ip_v.IPPrefix.Addr(), ip_v.NAT)
											ip_o[ip_i] = pDB_Peer_RI_IF_IP{
												IPPrefix:    ip_v.IPPrefix,
												Masked:      ip_v.IPPrefix.Masked(),
												Router_ID:   ip_v.Router_ID,
												Primary:     ip_v.Primary,
												Preferred:   ip_v.Preferred,
												NAT:         ip_v.NAT,
												DHCP:        ip_v.DHCP,
												Reserved:    ip_v.Reserved,
												Description: ip_v.Description,
											}
										}
										return
									}(),
									PARP: func() (parp_o map[netip.Addr]pDB_Peer_RI_IF_PARP) {
										parp_o = make(map[netip.Addr]pDB_Peer_RI_IF_PARP)
										for _, parp_v := range if_v.PARP {
											var (
												parp_i = parp_v.IPPrefix.Addr()
											)
											switch ip_if_v, flag := vIP_IF[parp_i]; flag {
											case true:
												log.Warnf("peer ASN '%v', RI '%v', IF '%v', Proxy_ARP IP '%v' already defined in IF '%v'; ACTION: skip.", value.ASN, ri_v.Name, if_v.Name, parp_i, ip_if_v)
												continue
											}
											vIP_IF[parp_i] = if_v.Name
											add_to_ab(true, false, "OUTTER_LIST", parp_v.IPPrefix.Addr(), parp_v.NAT)
											parp_o[parp_v.IPPrefix.Addr()] = pDB_Peer_RI_IF_PARP{
												IPPrefix:    parp_v.IPPrefix,
												NAT:         parp_v.NAT,
												Reserved:    parp_v.Reserved,
												Description: parp_v.Description,
											}
										}
										return
									}(),
									Disable:     if_v.Disable,
									Reserved:    if_v.Reserved,
									Description: if_v.Description,
								}
							}
							return
						}(),
						IP_IF:    vIP_IF,
						Policy:   ri_v.Policy.Parse(),
						Reserved: ri_v.Reserved,
						Description: func() (outbound _Description) {
							switch ri_v.Name == _juniper_mgmt_RI && len(ri_v.Description) == 0 {
							case true:
								return "MANAGEMENT-INSTANCE"
							}
							return ri_v.Description
						}(),
					}
				}
				return
			}()
		)
		pdb_peer[value.ASN] = pDB_peer{
			ASN:          value.ASN,
			ASN_PName:    vASN_PName,
			Router_ID:    vRouter_ID,
			RI:           vRI,
			IF_RI:        vIF_RI,
			Hostname:     vHostname,
			Version:      value.Version,
			Major:        vMajor,
			IKE_GCM:      vMajor >= 12.3,
			Manufacturer: value.Manufacturer,
			Model:        value.Model,
			Serial:       value.Serial,
			GT_Patch:     value.GT_Patch.Sanitize(),
			Root:         value.Root.Parse(16, "peer AS"+vASN_PName.String()+": root password is not acceptable"),
			GT_List:      vGT_List,
			Reserved:     value.Reserved,
			Description:  value.Description,
			VI:           map[_VI_ID]pDB_Peer_VI{},
			RM_ID:        &rm_id,
			AB:           &ab,
		}
	}

	for _, value := range xml_db.VI {
		switch value.Reserved {
		case true:
			continue
		}
		var (
			peers = len(value.Peer)
		)
		switch peers == 2 {
		case false:
			continue
		}
		func() {
			var (
				v_No_NAT = true
				v_NAT    = make([]netip.Addr, peers)
			)
			for peer_index := range value.Peer {
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN]; flag || !value.Peer[peer_index].Reserved {
				case false:
					return
				}
				value.Peer[peer_index].RI = value.Peer[peer_index].RI.Parse()
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI]; flag {
				case false:
					return
				}
				switch len(value.Peer[peer_index].IF) == 0 {
				case true:
					for if_i := range pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF {
						value.Peer[peer_index].IF = if_i
						log.Debugf("VI '%v', peer '%v', no interface defined; ACTION: found '%v'.", value.ID.String(), peer_index, value.Peer[peer_index].IF)
						break
					}
				case false:
					switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF]; flag {
					case false:
						return
					}
				}
				switch value.Peer[peer_index].IP.String() == "invalid IP" {
				case true:
					for ip_i := range pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].IP {
						value.Peer[peer_index].IP = ip_i
						log.Debugf("VI '%v', peer '%v', no IP defined; ACTION: found '%v'.", value.ID.String(), peer_index, value.Peer[peer_index].IP)
						break
					}
				}
				switch _, flag := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].IP[value.Peer[peer_index].IP]; flag {
				case false:
					return
				}
				switch nat := pdb_peer[value.Peer[peer_index].ASN].RI[value.Peer[peer_index].RI].IF[value.Peer[peer_index].IF].IP[value.Peer[peer_index].IP].NAT; nat.IsValid() {
				case true:
					v_NAT[peer_index] = nat
				case false:
					v_NAT[peer_index] = value.Peer[peer_index].IP
				}
				switch v_NAT[peer_index].IsValid() {
				case false:
					return
				}
				switch v_NAT[peer_index].IsPrivate() {
				case true:
					v_No_NAT = false
				}
			}
			pdb_peer[value.Peer[0].ASN].VI[value.ID] = pDB_Peer_VI{
				VI_ID_PName:          value.ID.Parse(),
				Type:                 value.Type,
				Communication:        value.Communication.Parse(_if_mode_vi),
				PSK:                  value.PSK.Parse(64),
				Route_Metric:         value.Route_Metric,
				IPPrefix:             get_vi_ipprefix(value.ID, 0),
				No_NAT:               v_No_NAT,
				IKE_GCM:              pdb_peer[value.Peer[0].ASN].IKE_GCM && pdb_peer[value.Peer[1].ASN].IKE_GCM,
				Left_ASN:             value.Peer[0].ASN,
				Left_RI:              value.Peer[0].RI,
				Left_IF:              value.Peer[0].IF,
				Left_IP:              value.Peer[0].IP,
				Left_NAT:             v_NAT[0],
				Left_Local_Address:   len(pdb_peer[value.Peer[0].ASN].RI[value.Peer[0].RI].IF[value.Peer[0].IF].IP) > 1,
				Left_Dynamic:         value.Peer[0].Dynamic,
				Left_Hub:             value.Peer[0].Hub,
				Left_Inner_RI:        value.Peer[0].Inner_RI.Parse(),
				Left_Inner_IPPrefix:  get_vi_ipprefix(value.ID, 1),
				Right_ASN:            value.Peer[1].ASN,
				Right_RI:             value.Peer[1].RI,
				Right_IF:             value.Peer[1].IF,
				Right_IP:             value.Peer[1].IP,
				Right_NAT:            v_NAT[1],
				Right_Local_Address:  len(pdb_peer[value.Peer[1].ASN].RI[value.Peer[1].RI].IF[value.Peer[1].IF].IP) > 1,
				Right_Dynamic:        value.Peer[1].Dynamic,
				Right_Hub:            value.Peer[1].Hub,
				Right_Inner_RI:       value.Peer[1].Inner_RI.Parse(),
				Right_Inner_IPPrefix: get_vi_ipprefix(value.ID, 2),
				Reserved:             value.Reserved,
				Description:          value.Description,
			}
			pdb_peer[value.Peer[1].ASN].VI[value.ID] = pDB_Peer_VI{
				VI_ID_PName:          pdb_peer[value.Peer[0].ASN].VI[value.ID].VI_ID_PName,
				Type:                 pdb_peer[value.Peer[0].ASN].VI[value.ID].Type,
				Communication:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Communication,
				PSK:                  pdb_peer[value.Peer[0].ASN].VI[value.ID].PSK,
				Route_Metric:         pdb_peer[value.Peer[0].ASN].VI[value.ID].Route_Metric,
				IPPrefix:             pdb_peer[value.Peer[0].ASN].VI[value.ID].IPPrefix,
				No_NAT:               pdb_peer[value.Peer[0].ASN].VI[value.ID].No_NAT,
				IKE_GCM:              pdb_peer[value.Peer[0].ASN].VI[value.ID].IKE_GCM,
				Left_ASN:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_ASN,
				Left_RI:              pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_RI,
				Left_IF:              pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_IF,
				Left_IP:              pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_IP,
				Left_NAT:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_NAT,
				Left_Local_Address:   pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Local_Address,
				Left_Dynamic:         pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Dynamic,
				Left_Hub:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Hub,
				Left_Inner_RI:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Inner_RI,
				Left_Inner_IPPrefix:  pdb_peer[value.Peer[0].ASN].VI[value.ID].Right_Inner_IPPrefix,
				Right_ASN:            pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_ASN,
				Right_RI:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_RI,
				Right_IF:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_IF,
				Right_IP:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_IP,
				Right_NAT:            pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_NAT,
				Right_Local_Address:  pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Local_Address,
				Right_Dynamic:        pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Dynamic,
				Right_Hub:            pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Hub,
				Right_Inner_RI:       pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Inner_RI,
				Right_Inner_IPPrefix: pdb_peer[value.Peer[0].ASN].VI[value.ID].Left_Inner_IPPrefix,
				Reserved:             pdb_peer[value.Peer[0].ASN].VI[value.ID].Reserved,
				Description:          pdb_peer[value.Peer[0].ASN].VI[value.ID].Description,
			}
			// log.Infof("'%+v'", pdb_peer[value.Peer[0].ASN].VI[value.ID])
			// log.Infof("'%+v'", pdb_peer[value.Peer[1].ASN].VI[value.ID])
		}()
	}
	return
}
func use_db() (err error) {
	for index, value := range pdb_peer {
		switch value.Reserved {
		case false:
			config[index] = make([]bytes.Buffer, len(value.GT_List)+1)
			for gt_i, gt_v := range value.GT_List {
				var (
					vGT_name = gt_v.String()
					vGT      *template.Template
					vBuf     bytes.Buffer
				)
				switch vGT, err = template.New(vGT_name).Funcs(gt_fm).Parse(pdb_gt[_GT_Name(vGT_name)].Content.String()); err == nil && vGT != nil {
				case true:
					switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
					case true:
						config[index][gt_i] = vBuf
					default:
						log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
						continue
					}
				default:
					log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
					continue
				}
			}
			// var (
			// 	vGT_name = "AS" + value.ASN_PName.String() + "_GT_Patch"
			// 	vGT      *template.Template
			// 	vBuf     bytes.Buffer
			// )
			// switch vGT, err = template.New(vGT_name).Funcs(gt_fm).Parse(value.GT_Patch.String()); err == nil && vGT != nil {
			// // switch vGT, err = template.New("config.tmpl").Funcs(gt_fm).ParseFiles("config.tmpl"); err == nil && vGT != nil {
			// case true:
			// 	switch err = vGT.Execute(&vBuf, value); err == nil && vGT != nil {
			// 	case true:
			// 		config[index][len(config[index])-1] = vBuf
			// 	default:
			// 		log.Warnf("peer '%v', template '%v' execute error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
			// 		continue
			// 	}
			// default:
			// 	log.Warnf("peer '%v', template '%v' parse error: '%v'; ACTION: skip.", index.String(), vGT_name, err)
			// 	continue
			// }
		}
	}
	return
}

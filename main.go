package main

import (
	"time"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
	// "golang.org/x/crypto/ssh"
)

func init() {
	log.SetLevel(_S_Verbosity)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:               false,
		DisableColors:             false,
		ForceQuote:                true,
		DisableQuote:              false,
		EnvironmentOverrideColors: false,
		DisableTimestamp:          false,
		FullTimestamp:             true,
		TimestampFormat:           time.RFC3339Nano,
		DisableSorting:            true,
		SortingFunc:               nil,
		DisableLevelTruncation:    false,
		PadLevelText:              true,
		QuoteEmptyFields:          true,
		FieldMap:                  nil,
		CallerPrettyfier:          nil,
	})
	log.SetReportCaller(false)
	ldap.DefaultTimeout = 5 * time.Second
}

func main() {
	defer log.Infof("done")
	log.Infof("start")

	i_file.read()

	define_iDB_Vocabulary()
	i_vi_ip.generate(_S_VI_IPPrefix, _VIx_IF_bits)
	i_ui_ip.generate(_S_UI_IPPrefix, _UIx_IP_bits)

	read_cDB()

	parse_iDB_Vocabulary()
	generate_iDB_host_list()

	read_ldap()
	parse_LDAP()

	i_peer.parse_GT()

	i_file.write()
	i_file_link.write()
	write_ldap()
}

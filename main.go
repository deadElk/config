package main

import (
	"time"

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
		DisableTimestamp:          true,
		FullTimestamp:             false,
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
}

func main() {
	switch {
	case !i_read_list.read():
		log.Fatalf("read_file() error; ACTION: fatal.")
	}

	define_iDB_Vocabulary()
	i_vi_ip.generate(_S_VI_IPPrefix, _VIx_IF_bits)
	i_ui_ip.generate(_S_UI_IPPrefix, _UIx_IP_bits)

	switch {
	case !read_cDB():
		log.Fatalf("read_cDB() error; ACTION: fatal.")
	}

	parse_iDB_Vocabulary()
	generate_iDB_host_list()

	switch {
	case !read_ldap():
		log.Fatalf("read_ldap() error; ACTION: fatal.")
	}
	switch {
	case !parse_LDAP():
		log.Fatalf("parse_LDAP() error; ACTION: fatal.")
	}
	switch {
	case !parse_GT():
		log.Fatalf("write_file() error; ACTION: fatal.")
	}
	switch {
	case !i_read_list.read():
		log.Fatalf("write_file() error; ACTION: fatal.")
	}
	switch {
	case !write_ldap():
		log.Fatalf("write_ldap() error; ACTION: fatal.")
	}
}

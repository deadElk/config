package main

import (
	"time"

	log "github.com/sirupsen/logrus"
	// "golang.org/x/crypto/ssh"
)

func init() {
	log.SetLevel(_S_loglevel)
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
	case !read_file():
		log.Fatalf("read_file() error; ACTION: fatal.")
	}
	define_iDB_Vocabulary()
	switch {
	case !read_cDB():
		log.Fatalf("write_file() error; ACTION: fatal.")
	}
	switch {
	case !parse_iDB():
		log.Fatalf("iDB parse error; ACTION: fatal.")
	}
	switch {
	case !parse_GT():
		log.Fatalf("GT parse error; ACTION: fatal.")
	}
	switch {
	case !write_file():
		log.Fatalf("write_file() error; ACTION: fatal.")
	}
}

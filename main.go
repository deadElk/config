package main

import (
	"time"

	log "github.com/sirupsen/logrus"
	// "golang.org/x/crypto/ssh"
)

func init() {
	log.SetLevel(_Defaults[_loglevel].(log.Level))
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    false,
		FullTimestamp:    true,
		PadLevelText:     true,
		ForceQuote:       true,
		QuoteEmptyFields: true,
		TimestampFormat:  time.RFC3339Nano,
	})
	log.SetReportCaller(true)
}
func main() {
	set_VI_IPPrefix()
	set_Domain_Name()
	switch err := db_read(); err == nil {
	case false:
		log.Fatalf("DB read error: '%v'", err)
		return
	}
	switch err := db_use(); err == nil {
	case false:
		log.Fatalf("DB use error: '%v'", err)
		return
	}
	switch err := config_upload(); err == nil {
	case false:
		log.Fatalf("config upload error: '%v'", err)
		return
	}
	switch err := config_test(); err == nil {
	case false:
		log.Fatalf("config test error: '%v'", err)
		return
	}
}

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
	_ = op()
}

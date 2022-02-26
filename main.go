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
	switch op() {
	case false:
		log.Fatalf("something wrong ....")
	}
	// log.Errorf("\n\n%v\n\n", i_ab)
	// log.Errorf("\n\n%v\n\n", i_ja)
	// log.Errorf("\n\n%v\n\n", i_ps)
	// log.Errorf("\n\n%v\n\n", i_ps)
	// log.Errorf("\n\n%v\n\n", i_vi)
	// log.Errorf("\n\n%v\n\n", i_vi_peer)
	// log.Errorf("\n\n%v\n\n", i_peer)
	// log.Errorf("\n\n%v\n\n", i_gt)
}

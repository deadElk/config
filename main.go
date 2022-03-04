package main

import (
	"time"

	log "github.com/sirupsen/logrus"
	// "golang.org/x/crypto/ssh"
)

func init() {
	log.SetLevel(_Defaults[_loglevel].(log.Level))
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
	switch op() {
	case false:
		log.Fatalf("something wrong ....")
	}
}

// Package sign implements a zone signer as a CoreDNS plugin.
package sign

import (
	"time"
)

// Sign holders signers that sign the various zones files.
type Sign struct {
	signers []*Signer
}

// OnStartup scans all signers and signs are resigns zones if needed.
func (s *Sign) OnStartup() error {
	for _, signer := range s.signers {
		why := signer.resign()
		if why == nil {
			continue
		}
		go signAndLog(signer, why)
	}
	return nil
}

// Various duration constants for signing the zones.
const (
	DurationExpireDays              = 14 * 24 * time.Hour // max time allowed before expiration
	DurationResignDays              = 6 * 24 * time.Hour  // if the last sign happenend this long ago, sign again
	DurationSignatureExpireDays     = 32 * 24 * time.Hour // sign for 32 days
	DurationRefreshHours            = 5 * time.Hour       // check zones every 5 hours
	DurationJitter                  = 3 * 24 * time.Hour  // default max jitter
	DurationSignatureInceptionHours = -3 * time.Hour      // -(2+1) hours, be sure to catch daylight saving time and such
)

const timeFmt = "2006-01-02T15:04:05.000Z07:00"

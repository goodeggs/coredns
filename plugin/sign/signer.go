package sign

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/file/tree"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("sign")

// Signer holds the data need to sign a zone file.
type Signer struct {
	keys      []Pair
	origin    string
	dbfile    string
	directory string
	jitter    time.Duration
	last      time.Time

	signedfile string
	stop       chan struct{}

	expiration uint32
	inception  uint32
	ttl        uint32
}

// Sign signs a zone file according to the parameters in s.
func (s *Signer) Sign(now time.Time) (*file.Zone, error) {
	rd, err := os.Open(s.dbfile)
	if err != nil {
		return nil, err
	}

	z, err := Parse(rd, s.origin, s.dbfile)
	if err != nil {
		return nil, err
	}

	s.inception, s.expiration = lifetime(now)

	s.ttl = z.Apex.SOA.Header().Ttl
	z.Apex.SOA.Serial = uint32(now.Unix())

	for _, pair := range s.keys {
		pair.Public.Header().Ttl = s.ttl // set TTL on key so it matches the RRSIG.
		z.Insert(pair.Public)
		z.Insert(pair.Public.ToDS(dns.SHA1))
		z.Insert(pair.Public.ToDS(dns.SHA256))
		z.Insert(pair.Public.ToDS(dns.SHA1).ToCDS())
		z.Insert(pair.Public.ToDS(dns.SHA256).ToCDS())
		z.Insert(pair.Public.ToCDNSKEY())
	}

	names, apex := names(s.origin, z)
	ln := len(names)

	var nsec *dns.NSEC
	if apex {
		nsec = NSEC(s.origin, names[(ln+1)%ln], s.ttl, []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC})
		z.Insert(nsec)
	}

	for _, pair := range s.keys {
		rrsig, err := pair.signRRs([]dns.RR{z.Apex.SOA}, s.origin, s.ttl, s.inception, s.expiration)
		if err != nil {
			return nil, err
		}
		z.Insert(rrsig)
		// NS apex may not be set if RR's have been discarded because the origin doesn't match.
		if len(z.Apex.NS) > 0 {
			rrsig, err = pair.signRRs(z.Apex.NS, s.origin, s.ttl, s.inception, s.expiration)
			if err != nil {
				return nil, err
			}
			z.Insert(rrsig)
		}
		if apex {
			rrsig, err = pair.signRRs([]dns.RR{nsec}, s.origin, s.ttl, s.inception, s.expiration)
			if err != nil {
				return nil, err
			}
			z.Insert(rrsig)
		}
	}

	// We are walking the tree in the same direction, so names[] can be used here to indicated the next element.
	i := 1
	err = z.Walk(func(e *tree.Elem, zrrs map[uint16][]dns.RR) error {
		if !apex && e.Name() == s.origin {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], s.ttl, append(e.Types(), dns.TypeNS, dns.TypeSOA, dns.TypeNSEC, dns.TypeRRSIG))
			z.Insert(nsec)
		} else {
			nsec := NSEC(e.Name(), names[(ln+i)%ln], s.ttl, append(e.Types(), dns.TypeNSEC, dns.TypeRRSIG))
			z.Insert(nsec)
		}

		for t, rrs := range zrrs {
			if t == dns.TypeRRSIG {
				continue
			}
			for _, pair := range s.keys {
				rrsig, err := pair.signRRs(rrs, s.origin, s.ttl, s.inception, s.expiration)
				if err != nil {
					return err
				}
				e.Insert(rrsig)
			}
		}
		i++
		return nil
	})
	if err == nil {
		s.last = now.Add(s.jitter)
	}
	return z, err
}

// resign checks if the signed zone exists, or needs resigning.
func (s *Signer) resign() error {
	signedfile := filepath.Join(s.directory, s.signedfile)
	rd, err := os.Open(signedfile)
	if err != nil && os.IsNotExist(err) {
		return err
	}

	now := time.Now().UTC()
	return resign(rd, now, s.last)
}

// resign will scan rd and check the signature on the SOA record. if last is not
// Zero it will be used to chck if we need to resign (DurationResignDays time has elapsed).
// If we fallthrough that check, it will check the remaining time on the SOA's RRSIG(s).
// When that signature has only 2 weeks left this we will also resign.
// If the SOA isn't found in the first 100 records, we will resign the zone.
func resign(rd io.Reader, now, last time.Time) error {
	if !last.IsZero() && now.Sub(last) >= DurationResignDays {
		return fmt.Errorf("resign was: %s ago", DurationResignDays)
	}

	zp := dns.NewZoneParser(rd, ".", "resign")
	zp.SetIncludeAllowed(true)
	i := 0
	expir := now.Add(DurationExpireDays) // If expiring within this time, resign.

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if err := zp.Err(); err != nil {
			return err
		}

		switch x := rr.(type) {
		case *dns.RRSIG:
			if x.TypeCovered == dns.TypeSOA {
				if !x.ValidityPeriod(expir) {
					return fmt.Errorf("signature expired: %s", expir.Format(timeFmt))
				}
			}
		}
		i++
		if i > 100 {
			return fmt.Errorf("no SOA RRSIG found in first 100 records")
		}
	}

	return nil
}

func signAndLog(s *Signer, why error) {
	now := time.Now().UTC()
	z, err := s.Sign(now)
	log.Infof("Signing %q because %s", s.origin, why)
	if err != nil {
		log.Warningf("Error signing %q with key tags %q in %s: %s. Next: %s", s.origin, keyTag(s.keys), time.Since(now), err, now.Add(DurationRefreshHours).Format(timeFmt))
		return
	}

	log.Infof("Successfully signed zone %q in %q with key tags %q and serial %d. elapsed %s, next: %s", s.origin, filepath.Join(s.directory, s.signedfile), keyTag(s.keys), z.Apex.SOA.Serial, time.Since(now), s.last.Add(DurationResignDays).Format(timeFmt))
	if err := s.write(z); err != nil {
		log.Warningf("Failed to move zone file: %s", err)
	}
}

// refresh checks every val if some zones need to be resigned.
func (s *Signer) refresh(val time.Duration) {
	tick := time.NewTicker(val)
	defer tick.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-tick.C:
			why := s.resign()
			if why == nil {
				continue
			}
			signAndLog(s, why)
		}
	}
}

func lifetime(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(DurationSignatureInceptionHours).Unix())
	expir := uint32(now.Add(DurationSignatureExpireDays).Unix())
	return incep, expir
}

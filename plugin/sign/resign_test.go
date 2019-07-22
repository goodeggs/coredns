package sign

import (
	"strings"
	"testing"
	"time"
)

func TestResignExpire(t *testing.T) {
	zr := strings.NewReader(`miek.nl.	1800	IN	RRSIG	SOA 13 2 1800 20190808191936 20190718161936 59725 miek.nl. eU6gI1OkSEbyt`)

	then := time.Date(2019, 7, 18, 22, 50, 0, 0, time.UTC)
	if x := resign(zr, then, then); x != nil {
		t.Errorf("Expected RRSIG to be valid for %s, got invalid: %s", then.Add(DurationExpireDays), x)
	}

	zr = strings.NewReader(`miek.nl.	1800	IN	RRSIG	SOA 13 2 1800 20190808191936 20190718161936 59725 miek.nl. eU6gI1OkSEbyt`)
	then = time.Date(2019, 8, 1, 22, 50, 0, 0, time.UTC)
	if x := resign(zr, then, then); x == nil {
		t.Errorf("Expected RRSIG to be invalid for %s, got valid", then.Add(DurationExpireDays))
	} else {
		t.Logf("Why: %s", x)
	}
}

func TestResignLast(t *testing.T) {
	zr := strings.NewReader(`miek.nl.	1800	IN	RRSIG	SOA 13 2 1800 20190808191936 20190718161936 59725 miek.nl. eU6gI1OkSEbyt`)
	then := time.Date(2019, 8, 1, 22, 50, 0, 0, time.UTC)
	// First test, signature expired, last should not be used.
	x := resign(zr, then, time.Time{})
	if x == nil {
		t.Errorf("Expected RRSIG to be expired, got valid")
	} else if !strings.Contains(x.Error(), "signature expired") {
		t.Errorf("Expected RRSIG to be expired, got: %s", x)
	}

	// Now set last to be within our resigning interval, so that should get triggered.
	last := then.Add(-2 * DurationResignDays)
	x = resign(zr, then, last)
	if x == nil {
		t.Errorf("Expected zone to be expired, got valid")
	} else if !strings.Contains(x.Error(), "resign was") {
		t.Errorf("Expected RRSIG be past resign, got: %s", x)
	}

}

package main

import (
	"testing"
	"time"
)

func TestUntilNextPeriod(t *testing.T) {
	boundary := time.Unix(1_800_000_000-1_800_000_000%totpPeriodSeconds, 0)
	cases := []struct {
		name string
		now  time.Time
		want time.Duration
	}{
		{"at a boundary, the whole next period", boundary, 30 * time.Second},
		{"just after a boundary", boundary.Add(time.Millisecond), 30*time.Second - time.Millisecond},
		{"mid period", boundary.Add(12 * time.Second), 18 * time.Second},
		{"just before a boundary", boundary.Add(30*time.Second - time.Nanosecond), time.Nanosecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := untilNextPeriod(tc.now)
			if got != tc.want {
				t.Fatalf("untilNextPeriod = %s, want %s", got, tc.want)
			}
			step := tc.now.Unix() / totpPeriodSeconds
			if next := tc.now.Add(got).Unix() / totpPeriodSeconds; next != step+1 {
				t.Fatalf("after the wait the step is %d, want %d", next, step+1)
			}
		})
	}
}

func TestTOTPCodeRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1, secret "12345678901234567890", last six digits.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 2000000000: "279037"} {
		got, err := totpCode(secret, time.Unix(unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("totpCode at %d = %s, want %s", unix, got, want)
		}
	}
}

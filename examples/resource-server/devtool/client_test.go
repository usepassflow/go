package main

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestUntilNextPeriod(t *testing.T) {
	cases := []struct {
		name   string
		period int
		offset time.Duration
		want   time.Duration
	}{
		{"at a boundary, the whole next period", 30, 0, 30 * time.Second},
		{"just after a boundary", 30, time.Millisecond, 30*time.Second - time.Millisecond},
		{"mid period", 30, 12 * time.Second, 18 * time.Second},
		{"just before a boundary", 30, 30*time.Second - time.Nanosecond, time.Nanosecond},
		{"60 s, at a boundary", 60, 0, 60 * time.Second},
		{"60 s, past the 30 s mark", 60, 42 * time.Second, 18 * time.Second},
		{"60 s, just before a boundary", 60, 60*time.Second - time.Nanosecond, time.Nanosecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			period := int64(tc.period)
			boundary := time.Unix(1_800_000_000-1_800_000_000%period, 0)
			now := boundary.Add(tc.offset)
			got := untilNextPeriod(now, tc.period)
			if got != tc.want {
				t.Fatalf("untilNextPeriod = %s, want %s", got, tc.want)
			}
			step := now.Unix() / period
			if next := now.Add(got).Unix() / period; next != step+1 {
				t.Fatalf("after the wait the step is %d, want %d", next, step+1)
			}
		})
	}
}

func TestTOTPCodeRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1, secret "12345678901234567890", last six digits.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 2000000000: "279037"} {
		got, err := totpCode(secret, totpParams{}, time.Unix(unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("totpCode at %d = %s, want %s", unix, got, want)
		}
	}
}

// TestTOTPCodeRFC6238EightDigits is the whole of RFC 6238 appendix B: 8 digits, 30 seconds, and
// the seed of each algorithm.
func TestTOTPCodeRFC6238EightDigits(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": strings.Repeat("1234567890", 6) + "1234",
	}
	vectors := []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, v := range vectors {
		for algorithm, want := range map[string]string{"SHA1": v.sha1, "SHA256": v.sha256, "SHA512": v.sha512} {
			secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(seeds[algorithm]))
			params := totpParams{Algorithm: algorithm, Digits: 8, Period: 30}
			got, err := totpCode(secret, params, time.Unix(v.unix, 0))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s at %d = %s, want %s", algorithm, v.unix, got, want)
			}
		}
	}
}

func TestTOTPCodePeriod(t *testing.T) {
	// With a 60 s period, 59 and 0 share a step, and 60 starts the next one.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	params := totpParams{Period: 60}
	at := func(unix int64) string {
		code, err := totpCode(secret, params, time.Unix(unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		return code
	}
	if at(59) != at(0) {
		t.Fatal("0 and 59 are in different 60 s periods")
	}
	if at(30) != at(0) {
		t.Fatal("0 and 30 are in different 60 s periods")
	}
	if at(60) == at(59) {
		t.Fatal("59 and 60 gave the same code")
	}
}

func TestTOTPCodeRefusesUnknownParams(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, params := range []totpParams{{Algorithm: "MD5"}, {Digits: 9}, {Period: -30}} {
		if _, err := totpCode(secret, params, time.Unix(59, 0)); err == nil {
			t.Errorf("totpCode accepted %+v", params)
		}
	}
}

func TestSetupParams(t *testing.T) {
	cases := []struct {
		name  string
		setup totpSetup
		want  totpParams
	}{
		{
			name:  "nothing said: the RFC 6238 defaults",
			setup: totpSetup{Secret: "S"},
			want:  totpParams{Algorithm: "SHA1", Digits: 6, Period: 30},
		},
		{
			name: "the otpauth URI names all three",
			setup: totpSetup{
				Secret:    "S",
				QRCodeURL: "otpauth://totp/Passflow:a%40example.com?algorithm=SHA512&digits=8&issuer=Passflow&period=60&secret=S",
			},
			want: totpParams{Algorithm: "SHA512", Digits: 8, Period: 60},
		},
		{
			name: "the fields win over the URI",
			setup: totpSetup{
				Secret:     "S",
				QRCodeURL:  "otpauth://totp/x?algorithm=SHA256&digits=6&period=30&secret=S",
				TOTPDigits: 8,
				TOTPPeriod: 60,
			},
			want: totpParams{Algorithm: "SHA256", Digits: 8, Period: 60},
		},
		{
			name:  "a lower-case algorithm",
			setup: totpSetup{Secret: "S", QRCodeURL: "otpauth://totp/x?algorithm=sha256&secret=S"},
			want:  totpParams{Algorithm: "SHA256", Digits: 6, Period: 30},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.setup.params()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("params = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSetupParamsRefusesABadURI(t *testing.T) {
	for _, uri := range []string{"otpauth://totp/x?digits=eight", "otpauth://totp/x?period=1m", "otpauth://totp/x?algorithm=MD5"} {
		if _, err := (totpSetup{Secret: "S", QRCodeURL: uri}).params(); err == nil {
			t.Errorf("params accepted %s", uri)
		}
	}
}

package ldaptime

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"24h", 24 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"30m", 30 * time.Minute, true},
		{"1d", 24 * time.Hour, true},
		{"bad", 0, false},
		{"xd", 0, false},
	}
	for _, c := range cases {
		got, err := ParseDuration(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("ParseDuration(%q) expected error", c.in)
		}
	}
}

func TestHuman(t *testing.T) {
	cases := map[time.Duration]string{
		0:                                     "0s",
		45 * time.Second:                      "45s",
		1238 * time.Second:                    "20m 38s",
		time.Hour + time.Minute + time.Second: "1h 1m",
		25 * time.Hour:                        "1d 1h",
		3 * 24 * time.Hour:                    "3d",
	}
	for d, want := range cases {
		if got := Human(d); got != want {
			t.Errorf("Human(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestFormat(t *testing.T) {
	in := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	if got := Format(in); got != "20260102150405Z" {
		t.Errorf("Format = %q", got)
	}
	// non-UTC input is normalized to UTC
	loc := time.FixedZone("x", 3600)
	if got := Format(time.Date(2026, 1, 2, 16, 4, 5, 0, loc)); got != "20260102150405Z" {
		t.Errorf("Format(non-UTC) = %q", got)
	}
}

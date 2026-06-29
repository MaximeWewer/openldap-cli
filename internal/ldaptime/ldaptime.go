// Package ldaptime parses human durations and formats LDAP generalizedTime.
package ldaptime

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration accepts Go durations plus a trailing-d days suffix (e.g. 7d).
func ParseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// Format renders an instant as an LDAP generalizedTime in UTC
// (e.g. 20060102150405Z), as used by reqStart and friends.
func Format(t time.Time) string { return t.UTC().Format("20060102150405") + "Z" }

// Human renders a duration compactly using its two largest non-zero units, so
// it scales from "45s" to "20m 38s" to "1h 5m" to "3d 4h".
func Human(d time.Duration) string {
	d = d.Round(time.Second)
	if d <= 0 {
		return "0s"
	}
	var parts []string
	add := func(n int64, unit string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d%s", n, unit))
		}
	}
	add(int64(d/(24*time.Hour)), "d")
	d %= 24 * time.Hour
	add(int64(d/time.Hour), "h")
	d %= time.Hour
	add(int64(d/time.Minute), "m")
	d %= time.Minute
	add(int64(d/time.Second), "s")
	if len(parts) > 2 { // keep the two most significant units
		parts = parts[:2]
	}
	return strings.Join(parts, " ")
}

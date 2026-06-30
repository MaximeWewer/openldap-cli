// Package humanize formats machine values into human-readable strings.
package humanize

import (
	"fmt"
	"strconv"
	"strings"
)

// Bytes formats a byte count with IEC binary units (KiB, MiB, GiB, …). LMDB
// sizes are powers of two, so binary units read cleanly: 1073741824 -> "1.0 GiB".
// Counts below 1 KiB are shown as plain bytes.
func Bytes(n int64) string {
	const unit = 1024
	if n < 0 {
		return "-" + Bytes(-n)
	}
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ParseBytes parses a human size into a byte count. It accepts a plain integer
// ("4294967296") or a number with a binary unit suffix, case-insensitively and
// treating decimal and IEC spellings as the same power of two: "4G", "4GB" and
// "4GiB" all mean 4 * 1024^3. Fractions are allowed ("1.5GiB"). The inverse of
// Bytes (modulo rounding).
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	numStr := s[:i]
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))
	if numStr == "" {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if num < 0 {
		return 0, fmt.Errorf("negative size %q", s)
	}
	var mult float64
	switch unit {
	case "", "B":
		mult = 1
	case "K", "KB", "KIB":
		mult = 1 << 10
	case "M", "MB", "MIB":
		mult = 1 << 20
	case "G", "GB", "GIB":
		mult = 1 << 30
	case "T", "TB", "TIB":
		mult = 1 << 40
	case "P", "PB", "PIB":
		mult = 1 << 50
	default:
		return 0, fmt.Errorf("unknown size unit %q in %q (use B, KiB, MiB, GiB, TiB, PiB)", unit, s)
	}
	return int64(num * mult), nil
}

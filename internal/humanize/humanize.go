// Package humanize formats machine values into human-readable strings.
package humanize

import "fmt"

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

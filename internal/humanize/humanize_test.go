package humanize

import "testing"

func TestBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{523747328, "499.5 MiB"}, // 127868 pages * 4096
		{1379958784, "1.3 GiB"},  // 336904 pages * 4096
		{1073741824, "1.0 GiB"},  // olcDbMaxSize 1 GiB
		{4294967296, "4.0 GiB"},  // olcDbMaxSize 4 GiB
		{1125899906842624, "1.0 PiB"},
		{-2048, "-2.0 KiB"},
	}
	for _, c := range cases {
		if got := Bytes(c.in); got != c.want {
			t.Errorf("Bytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

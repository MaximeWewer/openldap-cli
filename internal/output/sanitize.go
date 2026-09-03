package output

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Safe makes one directory value safe to print to a terminal.
//
// Attribute values are attacker-controlled: anyone who can write their own cn
// or description can put ESC sequences in one. Printed raw they let that person
// redraw the operator's screen - hide a line, fake a prompt, repaint an earlier
// result - and on terminals that answer OSC queries they can do worse. A value
// can also be raw binary (jpegPhoto, a certificate), which prints as garbage
// and can leave the terminal in a broken state.
//
// So every C0/C1 control and every invalid UTF-8 byte becomes a visible escape.
// Printable text, accents and CJK included, is returned untouched.
func Safe(v string) string { return escape(v, "") }

// SafeBlock is Safe for text a renderer laid out itself: it keeps the newlines
// and tabs that make up the layout and escapes everything else. Carriage return
// is NOT kept - it rewrites the line just printed, which is the cheapest way to
// forge output.
func SafeBlock(v string) string { return escape(v, "\n\t") }

// SafeAll is Safe over a slice, returning the input when nothing needed it.
func SafeAll(vs []string) []string {
	for i, v := range vs {
		if Safe(v) == v {
			continue
		}
		out := make([]string, len(vs))
		copy(out, vs[:i])
		for j := i; j < len(vs); j++ {
			out[j] = Safe(vs[j])
		}
		return out
	}
	return vs
}

// escape rewrites every control character and invalid byte as \xNN, except the
// ones listed in keep.
func escape(v, keep string) string {
	if !needsEscaping(v) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		switch {
		case r == utf8.RuneError && size == 1: // not valid UTF-8: a raw byte
			b.WriteString(`\x` + hexByte(v[i]))
		case r < utf8.RuneSelf && strings.ContainsRune(keep, r):
			b.WriteByte(v[i])
		case r < 0x20 || r == 0x7f, r >= 0x80 && r <= 0x9f: // C0, DEL, C1
			b.WriteString(`\x` + hexByte(byte(r)))
		default:
			b.WriteString(v[i : i+size])
		}
		i += size
	}
	return b.String()
}

func needsEscaping(v string) bool {
	for i := range len(v) {
		if c := v[i]; c < 0x20 || c == 0x7f || c >= 0x80 {
			return true // 0x80+ needs a UTF-8 pass to tell text from C1/binary
		}
	}
	return false
}

func hexByte(b byte) string {
	s := strconv.FormatUint(uint64(b), 16)
	if len(s) == 1 {
		return "0" + s
	}
	return s
}

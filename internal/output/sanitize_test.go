package output

import "testing"

func TestSafeEscapesTerminalControls(t *testing.T) {
	cases := map[string]string{
		"plain":            "plain",
		"Jean-Marc Éloi":   "Jean-Marc Éloi", // accents are text, keep them
		"漢字":               "漢字",
		"":                 "",
		"\x1b[2J\x1b[H":    `\x1b[2J\x1b[H`, // clear screen + home
		"a\x07b":           `a\x07b`,        // BEL
		"line\nnext":       `line\x0anext`,
		"tab\there":        `tab\x09here`,
		"del\x7f":          `del\x7f`,
		"\xc2\x9bc":        `\x9bc`, // C1 CSI, the 8-bit form of ESC[
		"bin\xff\xfe":      `bin\xff\xfe`,
		"\x1b]0;title\x07": `\x1b]0;title\x07`, // OSC window-title
	}
	for in, want := range cases {
		if got := Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeAllLeavesCleanInputAlone(t *testing.T) {
	in := []string{"a", "b"}
	if got := SafeAll(in); &got[0] != &in[0] {
		t.Error("SafeAll copied a slice that needed no change")
	}
	got := SafeAll([]string{"ok", "bad\x1b[31m"})
	if got[0] != "ok" || got[1] != `bad\x1b[31m` {
		t.Errorf("SafeAll = %q", got)
	}
}

func TestSafeBlockKeepsLayoutButNotCarriageReturn(t *testing.T) {
	// a renderer's own newlines and tabs are layout; CR would let a value
	// overwrite the line already printed
	cases := map[string]string{
		"one\ntwo":      "one\ntwo",
		"col\tcol":      "col\tcol",
		"a\rFAKE":       `a\x0dFAKE`,
		"row\n\x1b[1Ax": "row\n" + `\x1b[1Ax`,
	}
	for in, want := range cases {
		if got := SafeBlock(in); got != want {
			t.Errorf("SafeBlock(%q) = %q, want %q", in, got, want)
		}
	}
}

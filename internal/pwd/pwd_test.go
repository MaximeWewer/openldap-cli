package pwd

import (
	"strings"
	"testing"
)

func TestStrongLength(t *testing.T) {
	s, err := Strong(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 20 {
		t.Errorf("len = %d, want 20", len(s))
	}
}

func TestStrongMinimum(t *testing.T) {
	s, _ := Strong(4)
	if len(s) != 16 {
		t.Errorf("len = %d, want clamped to 16", len(s))
	}
}

func TestStrongHasAllClasses(t *testing.T) {
	s, _ := Strong(20)
	classes := map[string]string{"lower": lower, "upper": upper, "digit": digit, "sym": sym}
	for name, set := range classes {
		if !strings.ContainsAny(s, set) {
			t.Errorf("password %q missing a %s character", s, name)
		}
	}
}

func TestStrongIsRandom(t *testing.T) {
	a, _ := Strong(20)
	b, _ := Strong(20)
	if a == b {
		t.Errorf("two generations identical: %q", a)
	}
}

func TestHex(t *testing.T) {
	h, err := Hex(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 32 {
		t.Errorf("len = %d, want 32", len(h))
	}
	if strings.Trim(h, "0123456789abcdef") != "" {
		t.Errorf("non-hex chars in %q", h)
	}
}

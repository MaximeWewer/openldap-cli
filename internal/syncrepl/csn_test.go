package syncrepl

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	c := Parse("20240101120000.000000Z#000000#001#000000")
	if !c.OK {
		t.Fatal("did not parse a valid CSN")
	}
	if c.SID != "001" {
		t.Errorf("SID = %q, want 001", c.SID)
	}
	want := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	if !c.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", c.Time, want)
	}

	// a whole-second variant is tolerated
	if c := Parse("20240101120000Z#000000#abc#000000"); !c.OK || c.SID != "abc" {
		t.Errorf("whole-second CSN = %+v", c)
	}

	// garbage keeps Raw and reports not-OK rather than being dropped
	for _, bad := range []string{"", "not-a-csn", "20240101120000.000000Z#000000", "xxxx#0#1#0"} {
		if c := Parse(bad); c.OK {
			t.Errorf("Parse(%q) reported OK", bad)
		} else if c.Raw == "" && bad != "" {
			t.Errorf("Parse(%q) dropped Raw", bad)
		}
	}
}

func TestAssess(t *testing.T) {
	one := []string{"20240101120000.000000Z#000000#001#000000"}
	two := []string{
		"20240101120000.000000Z#000000#001#000000",
		"20240101120001.000000Z#000000#002#000000",
	}

	cases := []struct {
		name        string
		csn         []string
		hasSyncrepl bool
		mirror      bool
		role        string
		warnSub     string // "" = no warning expected
	}{
		{"true standalone", nil, false, false, "standalone", ""},
		{"provider serving replicas", one, false, false, "standalone", ""}, // one SID, no syncrepl
		{"replica in sync", one, true, false, "replica", ""},
		{"mirror node", two, true, true, "mirror", ""},
		// the two the old code could never surface:
		{"replica never synced", nil, true, false, "replica", "never received data"},
		{"multi-SID but called solo", two, false, false, "provider", ""},
	}
	for _, c := range cases {
		role, warns := Assess(c.csn, c.hasSyncrepl, c.mirror)
		if role != c.role {
			t.Errorf("%s: role = %q, want %q", c.name, role, c.role)
		}
		hasWarn := len(warns) > 0
		if hasWarn != (c.warnSub != "") {
			t.Errorf("%s: warnings = %v, want-substring %q", c.name, warns, c.warnSub)
			continue
		}
		if c.warnSub != "" && !containsSub(warns, c.warnSub) {
			t.Errorf("%s: warnings = %v, want one containing %q", c.name, warns, c.warnSub)
		}
	}

	// a "standalone" the data contradicts (>1 SID, no syncrepl) is caught as
	// role=provider — but if somehow labeled standalone it must warn. Exercise
	// the guard directly by asserting the multi-SID path warns nowhere silently:
	if _, w := Assess(two, false, false); len(w) != 0 {
		t.Errorf("provider role should not warn here: %v", w)
	}
}

func containsSub(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestSIDs(t *testing.T) {
	csns := ParseAll([]string{
		"20240101120000.000000Z#000000#001#000000",
		"20240101120001.000000Z#000000#002#000000",
		"20240101120002.000000Z#000000#001#000000", // 001 again
		"garbage",
	})
	got := SIDs(csns)
	if !reflect.DeepEqual(got, []string{"001", "002"}) {
		t.Errorf("SIDs = %v, want [001 002]", got)
	}
	// one SID => a single contributor
	if got := SIDs(ParseAll([]string{"20240101120000.000000Z#000000#001#000000"})); len(got) != 1 {
		t.Errorf("SIDs = %v, want one", got)
	}
	// nothing valid => empty, not a nil-deref
	if got := SIDs(ParseAll([]string{"junk"})); len(got) != 0 {
		t.Errorf("SIDs = %v, want none", got)
	}
}

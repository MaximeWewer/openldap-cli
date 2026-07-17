package limits

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseWho(t *testing.T) {
	cases := []struct {
		in   string
		want Who
	}{
		{"*", Who{Raw: "*", Kind: "*"}},
		{"anonymous", Who{Raw: "anonymous", Kind: "anonymous"}},
		{"users", Who{Raw: "users", Kind: "users"}},
		{"self", Who{Raw: "self", Kind: "self"}},

		// a bare dn= has no style, and base is the default
		{`dn="cn=app,dc=x"`, Who{Raw: `dn="cn=app,dc=x"`, Kind: "dn", Scope: "base", DN: "cn=app,dc=x"}},
		{`dn.exact="cn=app,dc=x"`, Who{Raw: `dn.exact="cn=app,dc=x"`, Kind: "dn", Scope: "base", DN: "cn=app,dc=x"}},
		{`dn.subtree="ou=u,dc=x"`, Who{Raw: `dn.subtree="ou=u,dc=x"`, Kind: "dn", Scope: "subtree", DN: "ou=u,dc=x"}},
		{`dn.onelevel="ou=u,dc=x"`, Who{Raw: `dn.onelevel="ou=u,dc=x"`, Kind: "dn", Scope: "one", DN: "ou=u,dc=x"}},
		{`dn.children="ou=u,dc=x"`, Who{Raw: `dn.children="ou=u,dc=x"`, Kind: "dn", Scope: "children", DN: "ou=u,dc=x"}},
		{`dn.regex="^cn=[^,]+,dc=x$"`, Who{Raw: `dn.regex="^cn=[^,]+,dc=x$"`, Kind: "dn", Scope: "regex", DN: "^cn=[^,]+,dc=x$"}},
		// dn[.<type>][.<style>]: type self/this sits before the style
		{`dn.this.subtree="ou=u,dc=x"`, Who{Raw: `dn.this.subtree="ou=u,dc=x"`, Kind: "dn", Type: "this", Scope: "subtree", DN: "ou=u,dc=x"}},

		{`group="cn=g,dc=x"`, Who{Raw: `group="cn=g,dc=x"`, Kind: "group", Group: "cn=g,dc=x"}},
		{`group/groupOfNames="cn=g,dc=x"`, Who{Raw: `group/groupOfNames="cn=g,dc=x"`, Kind: "group", Group: "cn=g,dc=x", OC: "groupofnames"}},
		{`group/groupOfNames/member="cn=g,dc=x"`, Who{Raw: `group/groupOfNames/member="cn=g,dc=x"`, Kind: "group", Group: "cn=g,dc=x", OC: "groupofnames", AT: "member"}},

		{"nonsense", Who{Raw: "nonsense", Kind: "other"}},
	}
	for _, c := range cases {
		if got := ParseWho(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseWho(%q) =\n  %+v\nwant\n  %+v", c.in, got, c.want)
		}
	}
}

func TestParseKeepsQuotedDNWhole(t *testing.T) {
	// a DN with a space would be split by a naive Fields()
	l := Parse(`{3}dn.exact="cn=Sales EMEA,dc=x" size=500 time=60`)
	if l.Index != 3 {
		t.Errorf("Index = %d, want 3", l.Index)
	}
	if l.Who.DN != "cn=sales emea,dc=x" {
		t.Errorf("DN = %q", l.Who.DN)
	}
	if !reflect.DeepEqual(l.Specs, []string{"size=500", "time=60"}) {
		t.Errorf("Specs = %v", l.Specs)
	}
}

func TestSameWho(t *testing.T) {
	// slapd reads these as the same identity, so they must not become two clauses
	same := [][2]string{
		{`dn.exact="cn=a,dc=x"`, `dn.base="cn=a,dc=x"`},
		{`dn.exact="cn=a,dc=x"`, `dn="cn=a,dc=x"`},
		{`dn.subtree="ou=u,dc=x"`, `dn.sub="ou=u,dc=x"`},
		{`dn.exact="CN=A,DC=X"`, `dn.exact="cn=a,dc=x"`},
		{`dn.onelevel="ou=u,dc=x"`, `dn.one="ou=u,dc=x"`},
	}
	for _, p := range same {
		if !SameWho(ParseWho(p[0]), ParseWho(p[1])) {
			t.Errorf("SameWho(%s, %s) = false, want true", p[0], p[1])
		}
	}
	diff := [][2]string{
		{`dn.exact="cn=a,dc=x"`, `dn.subtree="cn=a,dc=x"`},
		{`dn.exact="cn=a,dc=x"`, `dn.exact="cn=b,dc=x"`},
		{`group="cn=g,dc=x"`, `dn.exact="cn=g,dc=x"`},
		{`group/groupOfNames="cn=g,dc=x"`, `group/groupOfURLs="cn=g,dc=x"`},
		{"users", "anonymous"},
		{"nonsense", "nonsense"}, // unparsed never matches, not even itself
	}
	for _, p := range diff {
		if SameWho(ParseWho(p[0]), ParseWho(p[1])) {
			t.Errorf("SameWho(%s, %s) = true, want false", p[0], p[1])
		}
	}
}

func TestCovers(t *testing.T) {
	yes := [][2]string{
		{"*", "users"},
		{"*", "anonymous"},
		{"*", `dn.exact="cn=a,dc=x"`},
		{"users", `dn.exact="cn=a,dc=x"`},
		{"users", `group="cn=g,dc=x"`},
		{"users", "self"},
		{`dn.subtree="dc=x"`, `dn.exact="cn=a,ou=u,dc=x"`},
		{`dn.subtree="dc=x"`, `dn.subtree="ou=u,dc=x"`},
		{`dn.children="dc=x"`, `dn.exact="cn=a,ou=u,dc=x"`},
		{`dn.exact="cn=a,dc=x"`, `dn.base="cn=a,dc=x"`},
		{`dn.one="ou=u,dc=x"`, `dn.exact="cn=a,ou=u,dc=x"`},
	}
	for _, p := range yes {
		if !Covers(ParseWho(p[0]), ParseWho(p[1])) {
			t.Errorf("Covers(%s, %s) = false, want true", p[0], p[1])
		}
	}
	no := [][2]string{
		{"anonymous", "users"},
		{"users", "anonymous"},
		{"users", "*"},
		// a group's membership is in the directory, not in the clause
		{`group="cn=g,dc=x"`, `dn.exact="cn=a,dc=x"`},
		{`dn.exact="cn=a,dc=x"`, `group="cn=g,dc=x"`},
		// a regex is not something we can reason about
		{`dn.regex="^cn=.*,dc=x$"`, `dn.exact="cn=a,dc=x"`},
		{`dn.exact="dc=x"`, `dn.subtree="dc=x"`}, // exact does not cover a whole subtree
		{`dn.subtree="ou=u,dc=x"`, `dn.exact="cn=a,dc=x"`},
		// one level only reaches its immediate children
		{`dn.one="dc=x"`, `dn.exact="cn=a,ou=u,dc=x"`},
		{"nonsense", "users"},
	}
	for _, p := range no {
		if Covers(ParseWho(p[0]), ParseWho(p[1])) {
			t.Errorf("Covers(%s, %s) = true, want false", p[0], p[1])
		}
	}
}

func TestUpsertUpdatesInPlaceRatherThanAppending(t *testing.T) {
	// the bug this exists for: a second clause for the same identity is never
	// reached, because the first already decided
	vals := []string{`{0}dn.exact="cn=app,dc=x" size=500`}
	bodies, res, err := Upsert(vals, ParseWho(`dn.exact="cn=app,dc=x"`), []string{"size=5000"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "updated" {
		t.Errorf("Action = %q, want updated", res.Action)
	}
	if len(bodies) != 1 {
		t.Fatalf("appended instead of updating: %v", bodies)
	}
	if !strings.Contains(bodies[0], "size=5000") || strings.Contains(bodies[0], "size=500 ") {
		t.Errorf("body = %q", bodies[0])
	}
	// ...and the spelling of the existing clause does not matter
	vals = []string{`{0}dn.base="cn=app,dc=x" size=500`}
	if bodies, _, err = Upsert(vals, ParseWho(`dn.exact="cn=app,dc=x"`), []string{"size=5000"}); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 {
		t.Errorf("dn.base vs dn.exact read as different clauses: %v", bodies)
	}
}

func TestUpsertKeepsTheLimitsItWasNotAsked(t *testing.T) {
	// --size must not silently drop an existing time=
	vals := []string{`{0}dn.exact="cn=app,dc=x" size=500 time=60`}
	bodies, _, err := Upsert(vals, ParseWho(`dn.exact="cn=app,dc=x"`), []string{"size=5000"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bodies[0], "time=60") {
		t.Errorf("time= was dropped: %q", bodies[0])
	}
	if !strings.Contains(bodies[0], "size=5000") {
		t.Errorf("size= was not applied: %q", bodies[0])
	}
}

func TestUpsertPlacesANewClauseAboveOneThatWouldShadowIt(t *testing.T) {
	vals := []string{`{0}* size=500`}
	bodies, res, err := Upsert(vals, ParseWho(`dn.exact="cn=app,dc=x"`), []string{"size=unlimited"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "added" || res.At != 0 {
		t.Errorf("Action=%q At=%d, want added at 0", res.Action, res.At)
	}
	if res.ShadowedBy != "* size=500" {
		t.Errorf("ShadowedBy = %q", res.ShadowedBy)
	}
	if !strings.HasPrefix(bodies[0], `dn.exact="cn=app,dc=x"`) || bodies[1] != "* size=500" {
		t.Errorf("new clause not placed above the catch-all: %v", bodies)
	}
	// nothing shadowing => appended at the end, order otherwise untouched
	vals = []string{`{0}dn.exact="cn=other,dc=x" size=1`}
	if bodies, res, err = Upsert(vals, ParseWho(`dn.exact="cn=app,dc=x"`), []string{"size=2"}); err != nil {
		t.Fatal(err)
	}
	if res.At != 1 || res.ShadowedBy != "" || len(bodies) != 2 {
		t.Errorf("At=%d ShadowedBy=%q bodies=%v", res.At, res.ShadowedBy, bodies)
	}
}

func TestUpsertUnchangedIsReportedAsSuch(t *testing.T) {
	vals := []string{`{0}dn.exact="cn=app,dc=x" size=500`}
	_, res, err := Upsert(vals, ParseWho(`dn.exact="cn=app,dc=x"`), []string{"size=500"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "unchanged" {
		t.Errorf("Action = %q, want unchanged", res.Action)
	}
}

func TestRemoveTakesEveryDuplicate(t *testing.T) {
	// the wreckage the old append-only `set` left behind
	vals := []string{
		`{0}dn.exact="cn=app,dc=x" size=500`,
		`{1}* size=100`,
		`{2}dn.base="cn=app,dc=x" size=5000`,
	}
	bodies, removed, err := Remove(vals, ParseWho(`dn.exact="cn=app,dc=x"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 {
		t.Errorf("removed %d, want both duplicates", len(removed))
	}
	if !reflect.DeepEqual(bodies, []string{"* size=100"}) {
		t.Errorf("bodies = %v", bodies)
	}
	if _, _, err = Remove(vals, ParseWho(`dn.exact="cn=nobody,dc=x"`)); err == nil {
		t.Error("removing a clause that is not there should error")
	}
}

func TestLint(t *testing.T) {
	vals := []string{
		`{0}* size=500`,
		`{1}dn.exact="cn=app,dc=x" size=unlimited`, // never reached
	}
	f := Lint(vals)
	if len(f) != 1 || f[0].Index != 1 {
		t.Fatalf("findings = %+v", f)
	}
	if !strings.Contains(f[0].Message, "unreachable") {
		t.Errorf("message = %q", f[0].Message)
	}

	// the duplicate case gets its own wording
	dup := []string{
		`{0}dn.exact="cn=app,dc=x" size=500`,
		`{1}dn.exact="cn=app,dc=x" size=5000`,
	}
	if f = Lint(dup); len(f) != 1 || !strings.Contains(f[0].Message, "already sets limits") {
		t.Fatalf("findings = %+v", f)
	}

	// a correctly ordered list is clean
	ok := []string{
		`{0}dn.exact="cn=app,dc=x" size=unlimited`,
		`{1}* size=500`,
	}
	if f = Lint(ok); len(f) != 0 {
		t.Errorf("clean list reported %+v", f)
	}
}

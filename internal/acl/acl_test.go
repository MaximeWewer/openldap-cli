package acl

import (
	"slices"
	"strings"
	"testing"
)

func TestSplitIndexed(t *testing.T) {
	cases := []struct {
		in   string
		idx  int
		body string
	}{
		{"{2}to x", 2, "to x"},
		{"{12}foo", 12, "foo"},
		{"to x", -1, "to x"},
		{"{bad}x", -1, "{bad}x"},
	}
	for _, c := range cases {
		idx, body := SplitIndexed(c.in)
		if idx != c.idx || body != c.body {
			t.Errorf("SplitIndexed(%q) = (%d,%q), want (%d,%q)", c.in, idx, body, c.idx, c.body)
		}
	}
}

func TestInjectInsertsBeforeNone(t *testing.T) {
	svc := `cn=svc,ou=service-accounts,dc=example,dc=org`
	values := []string{
		`{0}to attrs=userPassword by self write by * none`,
		`{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`,
	}
	edit, appended := Inject(values, InjectOpts{Target: "ou=users,dc=example,dc=org", Who: DNWho(svc), Access: "read", At: -1})
	if appended {
		t.Fatal("expected insert, got append")
	}
	if edit.Delete != values[1] {
		t.Errorf("Delete = %q, want %q", edit.Delete, values[1])
	}
	want := `{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by dn.exact="` + svc + `" read by * none`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}
}

func TestInjectAppendsWhenMissing(t *testing.T) {
	svc := `cn=svc,ou=service-accounts,dc=example,dc=org`
	values := []string{`{0}to attrs=userPassword by * none`}
	edit, appended := Inject(values, InjectOpts{Target: "ou=contractors,dc=example,dc=org", Who: DNWho(svc), Access: "write", Terminator: "none", At: -1})
	if !appended {
		t.Fatal("expected append")
	}
	if edit.Delete != "" {
		t.Errorf("Delete = %q, want empty", edit.Delete)
	}
	want := `to dn.subtree="ou=contractors,dc=example,dc=org" by dn.exact="` + svc + `" write by * none`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}
}

func TestRemoveGrantee(t *testing.T) {
	svc := `cn=svc,ou=service-accounts,dc=example,dc=org`
	values := []string{
		`{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by dn.exact="` + svc + `" read by * none`,
		`{5}to dn.base="dc=example,dc=org" by * read`,
	}
	bodies, removed, dropped := RemoveGrantee(values, DNWho(svc))
	if removed != 1 || dropped != 0 {
		t.Fatalf("removed = %d, dropped = %d, want 1/0", removed, dropped)
	}
	want := []string{
		`to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`,
		`to dn.base="dc=example,dc=org" by * read`, // untouched rules are carried over
	}
	if !slices.Equal(bodies, want) {
		t.Errorf("bodies = %q, want %q", bodies, want)
	}
}

// A rule whose only clause was the revoked one must be dropped: slapd rejects a
// rule with no `by` clause ("no by clause(s) specified in access line"), which
// would fail the whole revoke.
func TestRemoveGranteeDropsClauselessRule(t *testing.T) {
	svc := `cn=probe,dc=example,dc=org`
	values := []string{
		`{0}to dn.subtree="ou=a,dc=example,dc=org" by dn.exact="` + svc + `" read`,
		`{1}to * by * read`,
	}
	bodies, removed, dropped := RemoveGrantee(values, DNWho(svc))
	if removed != 1 || dropped != 1 {
		t.Fatalf("removed = %d, dropped = %d, want 1/1", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to * by * read`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

// The `config acl grant` shape: revoking its only grantee leaves `by * break`,
// which neither grants nor denies — drop it rather than leave the leftover
// `acl lint` then flags.
func TestRemoveGranteeDropsNoOpLeftover(t *testing.T) {
	svc := `cn=probe,dc=example,dc=org`
	values := []string{
		`{0}to dn.base="ou=a,dc=example,dc=org" by dn.exact="` + svc + `" search by * break`,
		`{1}to dn.subtree="ou=a,dc=example,dc=org" by dn.exact="` + svc + `" read by * break`,
		`{2}to * by * read`,
	}
	bodies, removed, dropped := RemoveGrantee(values, DNWho(svc))
	if removed != 2 || dropped != 2 {
		t.Fatalf("removed = %d, dropped = %d, want 2/2", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to * by * read`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

// `by * none` is a deliberate deny, not leftover noise: keep the rule, or
// revoking a grantee would silently widen access to that subtree.
func TestRemoveGranteeKeepsExplicitDeny(t *testing.T) {
	svc := `cn=probe,dc=example,dc=org`
	values := []string{`{0}to dn.subtree="ou=a,dc=example,dc=org" by dn.exact="` + svc + `" read by * none`}
	bodies, removed, dropped := RemoveGrantee(values, DNWho(svc))
	if removed != 1 || dropped != 0 {
		t.Fatalf("removed = %d, dropped = %d, want 1/0", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to dn.subtree="ou=a,dc=example,dc=org" by * none`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

// The returned list is what replaces olcAccess wholesale, so it must be ordered
// by the current index — not by the order the server happened to return.
func TestRemoveGranteeReturnsRulesInIndexOrder(t *testing.T) {
	svc := `cn=probe,dc=example,dc=org`
	values := []string{
		`{2}to dn.base="c" by * read`,
		`{0}to dn.base="a" by dn.exact="` + svc + `" read by * break`,
		`{1}to dn.base="b" by * read`,
	}
	bodies, removed, dropped := RemoveGrantee(values, DNWho(svc))
	if removed != 1 || dropped != 1 {
		t.Fatalf("removed = %d, dropped = %d, want 1/1", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to dn.base="b" by * read`, `to dn.base="c" by * read`}) {
		t.Errorf("bodies = %q, want b then c", bodies)
	}
}

// `svc revoke --tree` must undo exactly one `svc grant` — the container rule
// and the entries rule for that tree — and nothing the account has elsewhere.
func TestRemoveGranteeOnScopesToOneTree(t *testing.T) {
	svc := `cn=app,ou=service-accounts,dc=example,dc=org`
	who := DNWho(svc)
	values := []string{
		// the two rules `svc grant --tree ou=users` emits
		`{0}to dn.base="ou=users,dc=example,dc=org" by ` + who + ` search by * break`,
		`{1}to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=cn=g,dc=example,dc=org) by ` + who + ` read by * break`,
		// a grant on another tree: must survive untouched
		`{2}to dn.base="ou=groups,dc=example,dc=org" by ` + who + ` search by * break`,
		`{3}to dn.subtree="ou=groups,dc=example,dc=org" by ` + who + ` read by * break`,
		`{4}to * by * read`,
	}
	bodies, removed, dropped := RemoveGranteeOn(values, who, "ou=users,dc=example,dc=org")
	if removed != 2 || dropped != 2 {
		t.Fatalf("removed = %d, dropped = %d, want 2/2", removed, dropped)
	}
	want := []string{
		`to dn.base="ou=groups,dc=example,dc=org" by ` + who + ` search by * break`,
		`to dn.subtree="ou=groups,dc=example,dc=org" by ` + who + ` read by * break`,
		`to * by * read`,
	}
	if !slices.Equal(bodies, want) {
		t.Errorf("bodies = %q, want %q", bodies, want)
	}
}

// Scoping by target must not strip a co-grantee's access from the same rule,
// and must leave a rule that still has clauses standing.
func TestRemoveGranteeOnKeepsCoGrantees(t *testing.T) {
	svc := `cn=app,ou=service-accounts,dc=example,dc=org`
	who := DNWho(svc)
	other := DNWho(`cn=other,ou=service-accounts,dc=example,dc=org`)
	values := []string{`{0}to dn.subtree="ou=users,dc=example,dc=org" by ` + who + ` read by ` + other + ` read by * break`}
	bodies, removed, dropped := RemoveGranteeOn(values, who, "ou=users,dc=example,dc=org")
	if removed != 1 || dropped != 0 {
		t.Fatalf("removed = %d, dropped = %d, want 1/0", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to dn.subtree="ou=users,dc=example,dc=org" by ` + other + ` read by * break`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

// A tree with no grant for that account is not an excuse to touch other rules.
func TestRemoveGranteeOnUnknownTree(t *testing.T) {
	who := DNWho(`cn=app,ou=service-accounts,dc=example,dc=org`)
	values := []string{`{0}to dn.subtree="ou=users,dc=example,dc=org" by ` + who + ` read by * break`}
	bodies, removed, dropped := RemoveGranteeOn(values, who, "ou=absent,dc=example,dc=org")
	if removed != 0 || dropped != 0 {
		t.Fatalf("removed = %d, dropped = %d, want 0/0", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to dn.subtree="ou=users,dc=example,dc=org" by ` + who + ` read by * break`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

// No match must mean no write at all, not a rewrite of every rule.
func TestRemoveGranteeNoMatch(t *testing.T) {
	values := []string{`{0}to * by * read`}
	bodies, removed, dropped := RemoveGrantee(values, DNWho("cn=absent,dc=x"))
	if removed != 0 || dropped != 0 {
		t.Errorf("expected no change, got removed=%d dropped=%d", removed, dropped)
	}
	if !slices.Equal(bodies, []string{`to * by * read`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

func TestReorder(t *testing.T) {
	// intentionally out of order to prove it sorts by index first
	vals := []string{"{5}to dn.subtree=g by X write by * none", "{8}to dn.subtree=g/sub by Y read by * none", "{0}to * by * break"}

	// move {8} above {5} -> position 1
	got, err := Reorder(vals, 2, 1)
	if err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	want := []string{"to * by * break", "to dn.subtree=g/sub by Y read by * none", "to dn.subtree=g by X write by * none"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pos %d = %q, want %q", i, got[i], want[i])
		}
	}

	// no-op move returns the sorted, unindexed bodies
	same, _ := Reorder(vals, 0, 0)
	if same[0] != "to * by * break" {
		t.Errorf("no-op first = %q", same[0])
	}

	// out of range
	if _, err := Reorder(vals, 0, 9); err == nil {
		t.Error("expected out-of-range error")
	}
	if _, err := Reorder(nil, 0, 0); err == nil {
		t.Error("expected empty error")
	}
}

func TestInjectGroupWho(t *testing.T) {
	g := `cn=readers,ou=groups,dc=example,dc=org`
	values := []string{`{4}to dn.subtree="ou=x,dc=example,dc=org" by dn.exact="cn=sa1,dc=example,dc=org" read by * none`}
	edit, appended := Inject(values, InjectOpts{Target: "ou=x,dc=example,dc=org", Who: GroupWho(g), Access: "read", At: -1})
	if appended {
		t.Fatal("expected insert into existing rule")
	}
	want := `{4}to dn.subtree="ou=x,dc=example,dc=org" by dn.exact="cn=sa1,dc=example,dc=org" read by group.exact="` + g + `" read by * none`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}
}

func TestInjectFilterScopeAndPlacement(t *testing.T) {
	sa := `cn=app,ou=service-accounts,dc=example,dc=org`
	// a plain subtree rule must NOT be matched by a filtered grant (different selector)
	values := []string{`{6}to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`}

	edit, isNew := Inject(values, InjectOpts{
		Target: "ou=users,dc=example,dc=org", Filter: "(memberOf=cn=g,dc=example,dc=org)",
		Who: DNWho(sa), Access: "read", At: 6,
	})
	if !isNew {
		t.Fatal("filtered grant must create a NEW rule, not edit the unfiltered one")
	}
	want := `{6}to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=cn=g,dc=example,dc=org) by dn.exact="` + sa + `" read by * break`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}

	// base scope + default break terminator, appended
	edit, isNew = Inject(nil, InjectOpts{Target: "ou=users,dc=example,dc=org", Scope: "base", Who: DNWho(sa), Access: "search", At: -1})
	if !isNew {
		t.Fatal("expected a new rule")
	}
	if edit.Add != `to dn.base="ou=users,dc=example,dc=org" by dn.exact="`+sa+`" search by * break` {
		t.Errorf("base rule = %q", edit.Add)
	}

	// a second grantee on the SAME selector joins the existing rule (before by * break)
	edit, isNew = Inject([]string{`{6}to dn.base="ou=users,dc=example,dc=org" by dn.exact="cn=a,dc=x" search by * break`},
		InjectOpts{Target: "ou=users,dc=example,dc=org", Scope: "base", Who: DNWho(sa), Access: "search", At: -1})
	if isNew {
		t.Fatal("expected to join the existing rule")
	}
	if !strings.Contains(edit.Add, `by dn.exact="cn=a,dc=x" search by dn.exact="`+sa+`" search by * break`) {
		t.Errorf("joined rule = %q", edit.Add)
	}
}

func TestInjectIsIdempotent(t *testing.T) {
	sa := `cn=app,dc=x`
	v := []string{`{4}to dn.subtree="ou=users,dc=x" by dn.exact="` + sa + `" read by * break`}
	edit, isNew := Inject(v, InjectOpts{Target: "ou=users,dc=x", Who: DNWho(sa), Access: "read", At: -1})
	if isNew || edit.Add != "" || edit.Delete != "" {
		t.Errorf("re-granting an existing clause must be a no-op, got %+v (new=%v)", edit, isNew)
	}
	// a different access level is still a change
	if e2, _ := Inject(v, InjectOpts{Target: "ou=users,dc=x", Who: DNWho(sa), Access: "write", At: -1}); e2.Add == "" {
		t.Error("a different access level must still be injected")
	}
}

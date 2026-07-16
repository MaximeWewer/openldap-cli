package acl

import (
	"slices"
	"testing"
)

func TestRenameDNRewritesEveryDNBearingToken(t *testing.T) {
	old := "cn=devs,ou=groups,dc=example,dc=org"
	nw := "cn=engineers,ou=groups,dc=example,dc=org"
	values := []string{
		// the grantee of a group grant
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by group.exact="` + old + `" read by * break`,
		// the same DN inside a filter — what `svc grant --members-of` emits
		`{1}to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=` + old + `) by * read`,
		// a rule protecting the entry itself
		`{2}to dn.base="` + old + `" by * read`,
		// untouched
		`{3}to * by * read`,
	}
	bodies, n, skipped := RenameDN(values, old, nw)
	if n != 3 {
		t.Fatalf("rewritten = %d, want 3", n)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none", skipped)
	}
	want := []string{
		`to dn.subtree="ou=users,dc=example,dc=org" by group.exact="` + nw + `" read by * break`,
		`to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=` + nw + `) by * read`,
		`to dn.base="` + nw + `" by * read`,
		`to * by * read`,
	}
	if !slices.Equal(bodies, want) {
		t.Errorf("bodies =\n%q\nwant\n%q", bodies, want)
	}
}

// Renaming a container must re-base the rules naming the entries BELOW it —
// their DNs moved too.
func TestRenameDNRebasesEntriesBeneath(t *testing.T) {
	old, nw := "ou=old,dc=example,dc=org", "ou=new,dc=example,dc=org"
	values := []string{
		`{0}to dn.subtree="ou=sub,` + old + `" by dn.exact="cn=app,` + old + `" read by * break`,
	}
	bodies, n, _ := RenameDN(values, old, nw)
	if n != 2 {
		t.Fatalf("rewritten = %d, want 2", n)
	}
	want := `to dn.subtree="ou=sub,` + nw + `" by dn.exact="cn=app,` + nw + `" read by * break`
	if bodies[0] != want {
		t.Errorf("body = %q, want %q", bodies[0], want)
	}
}

// A DN that merely starts with the old DN is a different entry: `ou=olds,dc=x`
// is not under `ou=old,dc=x`, and neither is a prefix match.
func TestRenameDNDoesNotMatchPrefixes(t *testing.T) {
	old, nw := "ou=old,dc=example,dc=org", "ou=new,dc=example,dc=org"
	values := []string{
		`{0}to dn.subtree="ou=olds,dc=example,dc=org" by * read`, // similar name, different entry
		`{1}to dn.subtree="ou=old,dc=example,dc=com" by * read`,  // different suffix
	}
	bodies, n, _ := RenameDN(values, old, nw)
	if n != 0 {
		t.Fatalf("rewritten = %d, want 0 — a prefix/near-miss is a different entry", n)
	}
	if !slices.Equal(bodies, []string{
		`to dn.subtree="ou=olds,dc=example,dc=org" by * read`,
		`to dn.subtree="ou=old,dc=example,dc=com" by * read`,
	}) {
		t.Errorf("bodies = %q", bodies)
	}
}

// A regex rule names the old DN but cannot be rewritten mechanically: report it
// rather than mangle a pattern.
func TestRenameDNSkipsRegexAndSet(t *testing.T) {
	old, nw := "ou=old,dc=example,dc=org", "ou=new,dc=example,dc=org"
	values := []string{
		`{0}to dn.regex="^cn=[^,]+,` + old + `$" by * read`,
		`{1}to * by set="this/manager & user/` + old + `" read`,
		`{2}to dn.base="` + old + `" by * read`,
	}
	bodies, n, skipped := RenameDN(values, old, nw)
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1 (only the plain rule)", n)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %d rules, want 2", len(skipped))
	}
	// the skipped rules must survive byte-for-byte
	if bodies[0] != `to dn.regex="^cn=[^,]+,`+old+`$" by * read` {
		t.Errorf("regex rule was modified: %q", bodies[0])
	}
	if bodies[1] != `to * by set="this/manager & user/`+old+`" read` {
		t.Errorf("set rule was modified: %q", bodies[1])
	}
	if bodies[2] != `to dn.base="`+nw+`" by * read` {
		t.Errorf("plain rule not rewritten: %q", bodies[2])
	}
}

// DNs compare case-insensitively, but the rest of the rule must not be touched.
func TestRenameDNIsCaseInsensitive(t *testing.T) {
	values := []string{`{0}to dn.base="CN=Devs,OU=Groups,DC=Example,DC=Org" by * read`}
	bodies, n, _ := RenameDN(values, "cn=devs,ou=groups,dc=example,dc=org", "cn=eng,ou=groups,dc=example,dc=org")
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1", n)
	}
	if bodies[0] != `to dn.base="cn=eng,ou=groups,dc=example,dc=org" by * read` {
		t.Errorf("body = %q", bodies[0])
	}
}

// Unquoted DN values are legal in olcAccess; they end at whitespace.
func TestRenameDNHandlesUnquotedValues(t *testing.T) {
	old, nw := "cn=devs,ou=groups,dc=example,dc=org", "cn=eng,ou=groups,dc=example,dc=org"
	values := []string{`{0}to * by group.exact=` + old + ` read by * break`}
	bodies, n, _ := RenameDN(values, old, nw)
	if n != 1 {
		t.Fatalf("rewritten = %d, want 1", n)
	}
	if bodies[0] != `to * by group.exact=`+nw+` read by * break` {
		t.Errorf("body = %q", bodies[0])
	}
}

// Nothing naming the old DN = nothing to write, and the list is preserved.
func TestRenameDNNoReferences(t *testing.T) {
	values := []string{`{1}to dn.base="dc=example,dc=org" by * read`, `{0}to * by * none`}
	bodies, n, skipped := RenameDN(values, "cn=absent,dc=example,dc=org", "cn=x,dc=example,dc=org")
	if n != 0 || skipped != nil {
		t.Fatalf("rewritten = %d, skipped = %v, want 0/nil", n, skipped)
	}
	// returned in index order, ready for a replace
	if !slices.Equal(bodies, []string{`to * by * none`, `to dn.base="dc=example,dc=org" by * read`}) {
		t.Errorf("bodies = %q", bodies)
	}
}

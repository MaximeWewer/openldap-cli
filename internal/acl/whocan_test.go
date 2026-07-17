package acl

import (
	"reflect"
	"testing"
)

func TestMatchDN(t *testing.T) {
	target := "cn=bob,ou=users,dc=example,dc=org"
	cases := []struct {
		body string
		want Match
	}{
		{`to * by * read`, MatchYes},
		{`to dn.subtree="ou=users,dc=example,dc=org" by * read`, MatchYes},
		{`to dn.subtree="dc=example,dc=org" by * read`, MatchYes},
		{`to dn.children="ou=users,dc=example,dc=org" by * read`, MatchYes},
		{`to dn.one="ou=users,dc=example,dc=org" by * read`, MatchYes},
		{`to dn.exact="cn=bob,ou=users,dc=example,dc=org" by * read`, MatchYes},
		// spelling must not matter
		{`to dn.base="cn=bob,ou=users,dc=example,dc=org" by * read`, MatchYes},
		{`to dn="cn=bob,ou=users,dc=example,dc=org" by * read`, MatchYes},
		{`to dn.exact="CN=Bob,OU=Users,DC=example,DC=org" by * read`, MatchYes},

		{`to dn.exact="cn=alice,ou=users,dc=example,dc=org" by * read`, MatchNo},
		{`to dn.subtree="ou=groups,dc=example,dc=org" by * read`, MatchNo},
		{`to dn.exact="ou=users,dc=example,dc=org" by * read`, MatchNo},
		// bob is two levels under, not one
		{`to dn.one="dc=example,dc=org" by * read`, MatchNo},

		// needs the entry's attributes, or a regex engine: not a "no"
		{`to dn.subtree="dc=example,dc=org" filter=(objectClass=inetOrgPerson) by * read`, MatchUnknown},
		{`to dn.regex="^cn=[^,]+,ou=users,dc=example,dc=org$" by * read`, MatchUnknown},
	}
	for _, c := range cases {
		if got := MatchDN(c.body, target); got != c.want {
			t.Errorf("MatchDN(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestGrantsWrite(t *testing.T) {
	cases := []struct {
		access          string
		grants, decided bool
	}{
		{"manage", true, true},
		{"write", true, true},
		{"read", false, true},
		{"search", false, true},
		{"none", false, true},
		{"disclose", false, true},
		// add/delete are each half of write, not write
		{"add", false, true},
		{"delete", false, true},
		// privilege sets
		{"=wrscd", true, true},
		{"+w", true, true},
		{"+m", true, true},
		{"=rscd", false, true},
		{"-w", false, true},
		// not something we can read
		{"", false, false},
		{"gibberish", false, false},
	}
	for _, c := range cases {
		g, d := GrantsWrite(c.access)
		if g != c.grants || d != c.decided {
			t.Errorf("GrantsWrite(%q) = (%v,%v), want (%v,%v)", c.access, g, d, c.grants, c.decided)
		}
	}
}

func TestGrants(t *testing.T) {
	// a group DN carries spaces, which a naive Fields() would split on; and
	// `by * break` has NO access token — <access> is optional, so `break` is the
	// control. Reading it as an access invents a level called "break".
	body := `to * by group.exact="cn=my team,ou=groups,dc=x" write by * break`
	want := []Grant{
		{Who: `group.exact="cn=my team,ou=groups,dc=x"`, Access: "write"},
		{Who: "*", Control: "break"},
	}
	if got := Grants(body); !reflect.DeepEqual(got, want) {
		t.Errorf("Grants =\n  %+v\nwant\n  %+v", got, want)
	}

	// all three positions present
	got := Grants(`to * by dn.exact="cn=a,dc=x" read stop`)
	if !reflect.DeepEqual(got, []Grant{{Who: `dn.exact="cn=a,dc=x"`, Access: "read", Control: "stop"}}) {
		t.Errorf("Grants = %+v", got)
	}
}

func TestWhoCanStopsAtTheFirstMatchingRule(t *testing.T) {
	// the proven model: slapd stops at the first rule whose `to` matches, even
	// when no `by` names you — the implicit `by * none stop`
	vals := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by dn.exact="cn=hr,dc=example,dc=org" write by * read`,
		`{1}to * by dn.exact="cn=super,dc=example,dc=org" write by * read`,
	}
	d := WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "")
	if !d.Settled {
		t.Error("Settled = false, want true")
	}
	if len(d.Rules) != 1 || d.Rules[0].Index != 0 {
		t.Fatalf("rules = %+v", d.Rules)
	}
	w, _ := d.WriteGrants()
	if len(w) != 1 || w[0].Who != `dn.exact="cn=hr,dc=example,dc=org"` {
		t.Errorf("write grants = %+v; cn=super must NOT appear — rule {0} already decided", w)
	}
}

func TestWhoCanFollowsCatchAllBreak(t *testing.T) {
	// this CLI's own grants end in `by * break` so they stay additive: the rules
	// below still get a say, and the answer must include them
	vals := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by group.exact="cn=app,dc=x" write by * break`,
		`{1}to * by dn.exact="cn=super,dc=example,dc=org" write by * none`,
	}
	d := WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "")
	if len(d.Rules) != 2 {
		t.Fatalf("break was not followed: %+v", d.Rules)
	}
	if !d.Rules[0].FellThrough || d.Rules[1].FellThrough {
		t.Errorf("FellThrough = %v/%v", d.Rules[0].FellThrough, d.Rules[1].FellThrough)
	}
	w, _ := d.WriteGrants()
	if len(w) != 2 {
		t.Errorf("write grants = %+v, want both app and super", w)
	}
	if !d.Settled {
		t.Error("rule {1} ends in `by * none`, so it settles it")
	}
}

func TestWhoCanReportsUndecidableRatherThanGuessing(t *testing.T) {
	vals := []string{
		`{0}to dn.subtree="dc=example,dc=org" filter=(objectClass=inetOrgPerson) by * read`,
		`{1}to * by dn.exact="cn=super,dc=example,dc=org" write by * none`,
	}
	d := WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "")
	if d.Undecidable == "" {
		t.Fatal("a filter rule must stop the evaluation, not be skipped")
	}
	if d.Settled {
		t.Error("Settled must stay false when we could not evaluate")
	}
	// it must NOT have walked on to {1} and claimed super can write
	if w, _ := d.WriteGrants(); len(w) != 0 {
		t.Errorf("claimed grants past an undecidable rule: %+v", w)
	}
}

func TestWhoCanNoRuleMatchesIsNotSettled(t *testing.T) {
	vals := []string{`{0}to dn.subtree="ou=groups,dc=example,dc=org" by * read`}
	d := WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "")
	if d.Settled || len(d.Rules) != 0 || d.Undecidable != "" {
		t.Errorf("decision = %+v", d)
	}
}

func TestWhoCanAttributeScoping(t *testing.T) {
	vals := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" attrs=userPassword by self write by * auth`,
		`{1}to dn.subtree="ou=users,dc=example,dc=org" by dn.exact="cn=hr,dc=example,dc=org" write by * read`,
	}
	// the general question: the userPassword rule decides only userPassword, so
	// it is set aside rather than treated as the decider
	d := WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "")
	if len(d.AttrOnly) != 1 {
		t.Errorf("AttrOnly = %+v", d.AttrOnly)
	}
	if len(d.Rules) != 1 || d.Rules[0].Index != 1 {
		t.Fatalf("rules = %+v", d.Rules)
	}

	// ...but asking about userPassword, it decides, and hr never gets a look in
	d = WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "userPassword")
	if len(d.Rules) != 1 || d.Rules[0].Index != 0 {
		t.Fatalf("rules = %+v", d.Rules)
	}
	w, _ := d.WriteGrants()
	if len(w) != 1 || w[0].Who != "self" {
		t.Errorf("write grants = %+v, want self only", w)
	}

	// an unrelated attribute skips the narrowed rule entirely
	d = WhoCan(vals, "cn=bob,ou=users,dc=example,dc=org", "mail")
	if len(d.Rules) != 1 || d.Rules[0].Index != 1 {
		t.Fatalf("rules = %+v", d.Rules)
	}
}

package acl

import (
	"strings"
	"testing"
)

// slapd.access(5): "The dn, filter, and attrs statements are additive; they can
// be used in sequence". A selector carrying more than one part must not let the
// later ones bleed into the DN.
func TestParseSelectorAdditiveParts(t *testing.T) {
	for _, tc := range []struct {
		in     string
		kind   string
		scope  string
		dn     string
		filter string
		attrs  string
	}{
		{`to *`, "*", "", "", "", ""},
		{`to dn.subtree="ou=users,dc=example,dc=org"`, "dn", "subtree", "ou=users,dc=example,dc=org", "", ""},
		// the bug: `attrs=` used to end up inside the DN
		{`to dn.subtree="ou=users,dc=example,dc=org" attrs=mail`, "dn", "subtree", "ou=users,dc=example,dc=org", "", "mail"},
		{`to dn.subtree="ou=users,dc=example,dc=org" filter=(objectClass=person) attrs=cn,mail`,
			"dn", "subtree", "ou=users,dc=example,dc=org", "(objectclass=person)", "cn,mail"},
		// a filter carrying parens must stay in one piece
		{`to dn.base="dc=example,dc=org" filter=(&(a=b)(c=d))`, "dn", "base", "dc=example,dc=org", "(&(a=b)(c=d))", ""},
		{`to attrs=userPassword`, "attrs", "", "", "", "userpassword"},
		{`to attrs=userPassword,shadowLastChange`, "attrs", "", "", "", "userpassword,shadowlastchange"},
	} {
		got := parseSelector(tc.in)
		if got.kind != tc.kind || got.scope != tc.scope || got.dn != tc.dn || got.filter != tc.filter || got.attrs != tc.attrs {
			t.Errorf("parseSelector(%q) =\n  kind=%q scope=%q dn=%q filter=%v attrs=%q\nwant\n  kind=%q scope=%q dn=%q filter=%v attrs=%q",
				tc.in, got.kind, got.scope, got.dn, got.filter, got.attrs, tc.kind, tc.scope, tc.dn, tc.filter, tc.attrs)
		}
	}
}

// slapd.access(5) lists base/baseObject/exact, one/onelevel, sub/subtree,
// children. Treating a synonym as unknown makes covers() give up on an ordinary
// rule, so every spelling must land on the same scope.
func TestParseSelectorScopeSynonyms(t *testing.T) {
	for in, want := range map[string]string{
		`to dn.base="dc=x"`:       "base",
		`to dn.baseObject="dc=x"`: "base",
		`to dn.exact="dc=x"`:      "base",
		`to dn.one="dc=x"`:        "one",
		`to dn.onelevel="dc=x"`:   "one",
		`to dn.sub="dc=x"`:        "subtree",
		`to dn.subtree="dc=x"`:    "subtree",
		`to dn.children="dc=x"`:   "children",
		`to dn.regex="dc=.*"`:     "regex",
		// slapd.access(5): "<dnstyle> is optional … base, the default"
		`to dn="dc=x"`: "base",
	} {
		if got := parseSelector(in); got.scope != want || got.kind != "dn" {
			t.Errorf("parseSelector(%q) = kind=%q scope=%q, want kind=dn scope=%q", in, got.kind, got.scope, want)
		}
	}
}

// The proven case: a `dn.sub=` rule shadows the rule below it, and slapd denies.
// covers() must see it — ShadowIndex uses this to place grants, so a blind spot
// here appends a grant under the rule that kills it.
func TestCoversSubSynonymShadows(t *testing.T) {
	broad := parseSelector(`to dn.sub="ou=q,dc=example,dc=org"`)
	narrow := parseSelector(`to dn.subtree="cn=child,ou=q,dc=example,dc=org"`)
	if !covers(broad, narrow) {
		t.Error("covers(dn.sub=..., narrower) = false; slapd shadows it, so this must be true")
	}
}

// An entry-level rule matches every attribute, so it covers an attribute-scoped
// rule for the same tree — the second proven false negative.
func TestCoversEntryRuleShadowsAttrsRule(t *testing.T) {
	broad := parseSelector(`to dn.subtree="ou=q,dc=example,dc=org"`)
	narrow := parseSelector(`to dn.subtree="ou=q,dc=example,dc=org" attrs=cn`)
	if !covers(broad, narrow) {
		t.Error("covers(entry rule, attrs rule) = false; slapd shadows it, so this must be true")
	}
	// ...but not the other way round: attrs=cn says nothing about other attributes
	if covers(narrow, broad) {
		t.Error("covers(attrs rule, entry rule) = true; it only decides for cn")
	}
	// two different attribute lists never cover each other
	other := parseSelector(`to dn.subtree="ou=q,dc=example,dc=org" attrs=mail`)
	if covers(narrow, other) || covers(other, narrow) {
		t.Error("rules on disjoint attribute lists must not cover each other")
	}
}

func TestCoversOneLevel(t *testing.T) {
	a := parseSelector(`to dn.one="ou=q,dc=example,dc=org"`)
	// exactly one level under: covered
	if !covers(a, parseSelector(`to dn.base="cn=kid,ou=q,dc=example,dc=org"`)) {
		t.Error("dn.one must cover an entry exactly one level under it")
	}
	// two levels under: dn.one does not match it
	if covers(a, parseSelector(`to dn.base="cn=x,ou=sub,ou=q,dc=example,dc=org"`)) {
		t.Error("dn.one must not cover an entry two levels under it")
	}
	// a whole subtree below is not fully matched by a one-level rule
	if covers(a, parseSelector(`to dn.subtree="cn=kid,ou=q,dc=example,dc=org"`)) {
		t.Error("dn.one must not cover a subtree")
	}
}

// Inject must find the EXISTING rule for a target however it is spelled, or it
// adds a second rule slapd never reaches (the first already decided).
func TestInjectMatchesSpellingVariants(t *testing.T) {
	who := DNWho("cn=app,dc=example,dc=org")
	o := InjectOpts{Target: "ou=users,dc=example,dc=org", Scope: "subtree", Who: who, Access: "read", At: -1}
	for _, spelling := range []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by * none`,
		`{0}to dn.sub="ou=users,dc=example,dc=org" by * none`,
		`{0}to dn.sub="OU=Users,DC=Example,DC=Org" by * none`, // DNs compare case-insensitively
	} {
		edit, appended := Inject([]string{spelling}, o)
		if appended {
			t.Errorf("Inject(%q): created a second rule for the same target", spelling)
		}
		if !strings.Contains(edit.Add, who) {
			t.Errorf("Inject(%q): clause not added to the existing rule (Add=%q)", spelling, edit.Add)
		}
	}
	// base and subtree are different targets — no merging across them
	if _, appended := Inject([]string{`{0}to dn.base="ou=users,dc=example,dc=org" by * none`}, o); !appended {
		t.Error("Inject: a dn.base rule must not absorb a dn.subtree grant")
	}
}

// A rule narrowed by a filter or an attribute list is a different rule: adding
// the clause there would grant on entries the caller never asked about.
func TestInjectDoesNotMatchNarrowedRules(t *testing.T) {
	o := InjectOpts{Target: "ou=users,dc=example,dc=org", Scope: "subtree",
		Who: DNWho("cn=app,dc=example,dc=org"), Access: "read", At: -1}
	for _, narrowed := range []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=cn=g,dc=example,dc=org) by * none`,
		`{0}to dn.subtree="ou=users,dc=example,dc=org" attrs=mail by * none`,
	} {
		if _, appended := Inject([]string{narrowed}, o); !appended {
			t.Errorf("Inject(%q): merged into a narrowed rule; it must make its own", narrowed)
		}
	}
	// ...and a grant WITH the same filter does find its rule
	f := InjectOpts{Target: "ou=users,dc=example,dc=org", Scope: "subtree",
		Filter: "(memberOf=cn=g,dc=example,dc=org)", Who: DNWho("cn=app,dc=example,dc=org"), Access: "read", At: -1}
	if _, appended := Inject([]string{`{0}to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=cn=g,dc=example,dc=org) by * none`}, f); appended {
		t.Error("Inject: a grant with the same filter must reuse that rule")
	}
	// two DIFFERENT filters must never be merged
	g := f
	g.Filter = "(memberOf=cn=other,dc=example,dc=org)"
	if _, appended := Inject([]string{`{0}to dn.subtree="ou=users,dc=example,dc=org" filter=(memberOf=cn=g,dc=example,dc=org) by * none`}, g); !appended {
		t.Error("Inject: rules with different filters were treated as the same rule")
	}
}

// A regex target cannot be reasoned about statically: claiming coverage would
// call live rules dead.
func TestCoversRegexIsNeverProvable(t *testing.T) {
	a := parseSelector(`to dn.regex="^cn=[^,]+,ou=q,dc=example,dc=org$"`)
	if covers(a, parseSelector(`to dn.base="cn=kid,ou=q,dc=example,dc=org"`)) {
		t.Error("a regex selector must not be treated as covering")
	}
}

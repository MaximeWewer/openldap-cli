package acl

import "testing"

// slapd.access(5): "The dn, filter, and attrs statements are additive; they can
// be used in sequence". A selector carrying more than one part must not let the
// later ones bleed into the DN.
func TestParseSelectorAdditiveParts(t *testing.T) {
	for _, tc := range []struct {
		in     string
		kind   string
		scope  string
		dn     string
		filter bool
		attrs  string
	}{
		{`to *`, "*", "", "", false, ""},
		{`to dn.subtree="ou=users,dc=example,dc=org"`, "dn", "subtree", "ou=users,dc=example,dc=org", false, ""},
		// the bug: `attrs=` used to end up inside the DN
		{`to dn.subtree="ou=users,dc=example,dc=org" attrs=mail`, "dn", "subtree", "ou=users,dc=example,dc=org", false, "mail"},
		{`to dn.subtree="ou=users,dc=example,dc=org" filter=(objectClass=person) attrs=cn,mail`,
			"dn", "subtree", "ou=users,dc=example,dc=org", true, "cn,mail"},
		// a filter carrying spaces and parens must stay in one piece
		{`to dn.base="dc=example,dc=org" filter=(&(a=b)(c=d))`, "dn", "base", "dc=example,dc=org", true, ""},
		{`to attrs=userPassword`, "attrs", "", "", false, "userpassword"},
		{`to attrs=userPassword,shadowLastChange`, "attrs", "", "", false, "userpassword,shadowlastchange"},
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

// A regex target cannot be reasoned about statically: claiming coverage would
// call live rules dead.
func TestCoversRegexIsNeverProvable(t *testing.T) {
	a := parseSelector(`to dn.regex="^cn=[^,]+,ou=q,dc=example,dc=org$"`)
	if covers(a, parseSelector(`to dn.base="cn=kid,ou=q,dc=example,dc=org"`)) {
		t.Error("a regex selector must not be treated as covering")
	}
}

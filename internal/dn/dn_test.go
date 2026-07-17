package dn

import "testing"

func TestEscapeValue(t *testing.T) {
	for in, want := range map[string]string{
		// ordinary names must come back byte-for-byte
		"toto.titi":  "toto.titi",
		"devs":       "devs",
		"e2e.svc":    "e2e.svc",
		"Sales EMEA": "Sales EMEA", // an inner space is plain text
		"":           "",

		// RFC 4514 specials
		`acme,inc`:   `acme\,inc`,
		`jean+marie`: `jean\+marie`,
		`a"b`:        `a\"b`,
		`a;b`:        `a\;b`,
		`a<b>c`:      `a\<b\>c`,
		`a\b`:        `a\\b`,

		// position-dependent: only at the ends
		" lead":  `\ lead`,
		"trail ": `trail\ `,
		"#hash":  `\#hash`,
		"a#b":    "a#b", // a '#' elsewhere is not special

		// `=` stays: slapd reads cn=a=b as the value "a=b"
		"a=b": "a=b",
	} {
		if got := EscapeValue(in); got != want {
			t.Errorf("EscapeValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeValueNullByte(t *testing.T) {
	if got := EscapeValue("a\x00b"); got != `a\00b` {
		t.Errorf("EscapeValue(null) = %q", got)
	}
}

func TestSplit(t *testing.T) {
	cases := []struct{ in, rdn, parent string }{
		{"cn=bob,ou=users,dc=example,dc=org", "cn=bob", "ou=users,dc=example,dc=org"},
		{"dc=example,dc=org", "dc=example", "dc=org"},
		{"dc=org", "dc=org", ""},
		{"", "", ""},

		// the escaped comma is part of the NAME: cutting there would name a
		// parent of `inc,ou=groups,dc=x`, which does not exist
		{`cn=acme\,inc,ou=groups,dc=x`, `cn=acme\,inc`, "ou=groups,dc=x"},
		{`cn=a\\,ou=x`, `cn=a\\`, "ou=x"}, // trailing escaped backslash, then a real separator
		// a multi-valued RDN stays whole
		{"cn=a+uid=b,ou=users,dc=x", "cn=a+uid=b", "ou=users,dc=x"},
		// the server's hex form carries no literal comma, so it splits plainly
		{`cn=acme\2Cinc,ou=groups,dc=x`, `cn=acme\2Cinc`, "ou=groups,dc=x"},
	}
	for _, c := range cases {
		rdn, parent := Split(c.in)
		if rdn != c.rdn || parent != c.parent {
			t.Errorf("Split(%q) = (%q, %q), want (%q, %q)", c.in, rdn, parent, c.rdn, c.parent)
		}
	}
}

func TestReplaceRDN(t *testing.T) {
	// the point: the parent is KEPT, not re-derived from a configured base
	if got := ReplaceRDN("cn=bob,ou=eu,ou=users,dc=x", "cn=rob"); got != "cn=rob,ou=eu,ou=users,dc=x" {
		t.Errorf("ReplaceRDN = %q", got)
	}
	if got := ReplaceRDN(`cn=acme\,inc,ou=groups,dc=x`, "cn=acme"); got != "cn=acme,ou=groups,dc=x" {
		t.Errorf("ReplaceRDN with an escaped comma = %q", got)
	}
	if got := ReplaceRDN("dc=org", "dc=com"); got != "dc=com" {
		t.Errorf("ReplaceRDN with no parent = %q", got)
	}
}

func TestJoin(t *testing.T) {
	if got := Join("cn=devs", "ou=groups", "dc=example,dc=org"); got != "cn=devs,ou=groups,dc=example,dc=org" {
		t.Errorf("Join = %q", got)
	}
	// an empty part is dropped, so an optional OU needs no branch at the caller
	if got := Join("cn=devs", "", "dc=example,dc=org"); got != "cn=devs,dc=example,dc=org" {
		t.Errorf("Join with an empty part = %q", got)
	}
	if got := Join("cn=devs"); got != "cn=devs" {
		t.Errorf("Join with no parts = %q", got)
	}
}

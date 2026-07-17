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

package ldapx

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/MaximeWewer/openldap-cli/internal/dn"
)

// internal/dn re-implements RFC 4514 escaping so the domain package can build
// DNs without an LDAP dependency. This is the guard against it drifting from
// the library the rest of the CLI actually talks through.
func TestEscapeValueMatchesLibrary(t *testing.T) {
	for _, v := range []string{
		"toto.titi", "devs", "", "Sales EMEA",
		`acme,inc`, `jean+marie`, `a"b`, `a;b`, `a<b>c`, `a\b`,
		" lead", "trail ", "#hash", "a#b", "a=b", "a\x00b",
		`O'Brien & Sons, Ltd.`, "é.accent",
	} {
		if got, want := dn.EscapeValue(v), ldap.EscapeDN(v); got != want {
			t.Errorf("EscapeValue(%q) = %q, but go-ldap gives %q", v, got, want)
		}
	}
}

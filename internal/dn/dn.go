// Package dn builds distinguished names safely.
//
// A DN is assembled from text — `cn=<name>,<base>` — so a name carrying a `,`
// or a `+` does not stay a name: it becomes DN syntax, and the entry lands
// somewhere else or the server rejects the whole thing with a bare
// `Invalid DN Syntax`. RFC 4514 says which characters have to be escaped; this
// is that, kept free of any LDAP library so `domain` (the org-conventions
// package) can build DNs without depending on one.
package dn

import "strings"

// EscapeValue escapes an RDN value as RFC 4514 requires: the characters
// `"+,;<>\`, a leading `#`, leading or trailing spaces, and the null byte.
//
// `=` is deliberately left alone — RFC 4514 does not require escaping it inside
// a value, and slapd reads `cn=a=b` as the single value `a=b`.
//
// Ordinary names come back untouched, so this is safe to apply everywhere.
func EscapeValue(v string) string {
	if v == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(v))
	for i, r := range v {
		switch {
		// a space only needs escaping at either end; inside it is plain text
		case r == ' ' && (i == 0 || i == len(v)-1):
			b.WriteString(`\ `)
		case r == '#' && i == 0:
			b.WriteString(`\#`)
		case r == '"' || r == '+' || r == ',' || r == ';' || r == '<' || r == '>' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\x00':
			b.WriteString(`\00`) // a null byte cannot be escaped by a backslash alone
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Split splits a DN into its first RDN and the parent DN below it:
// `cn=bob,ou=users,dc=x` -> ("cn=bob", "ou=users,dc=x"). A DN with no parent
// returns ("", "") for the parent.
//
// It honors RFC 4514 escaping, which a `strings.SplitN(dn, ",", 2)` does not: in
// `cn=acme\,inc,ou=groups,dc=x` the first comma is part of the NAME, and cutting
// there yields the parent `inc,ou=groups,dc=x` — a DN that does not exist. A
// multi-valued RDN (`cn=a+uid=b,…`) is likewise kept whole.
func Split(dn string) (rdn, parent string) {
	esc := false
	for i := range len(dn) {
		switch {
		case esc:
			esc = false
		case dn[i] == '\\':
			esc = true
		case dn[i] == ',':
			return dn[:i], dn[i+1:]
		}
	}
	return dn, ""
}

// Parent returns the DN above dn, or "" when it has none.
func Parent(dn string) string {
	_, parent := Split(dn)
	return parent
}

// ReplaceRDN returns the DN an in-place modrdn produces: rdn where dn's first
// RDN was, same parent.
//
// The parent comes from the DN the server gave us, never from re-deriving the
// path: an entry found by subtree search may sit under a nested OU, and
// rebuilding its DN from the configured base silently names a different entry.
//
// rdn is taken as-is: escape its value with EscapeValue first.
func ReplaceRDN(dn, rdn string) string {
	parent := Parent(dn)
	if parent == "" {
		return rdn
	}
	return rdn + "," + parent
}

// Join builds a DN from an escaped RDN and the parent DN parts. Empty parts are
// dropped, so a caller can pass an optional OU without branching.
//
// rdn is taken as-is: escape its value with EscapeValue first.
func Join(rdn string, parts ...string) string {
	out := []string{rdn}
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

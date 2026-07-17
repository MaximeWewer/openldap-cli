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

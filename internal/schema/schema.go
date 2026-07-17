// Package schema parses RFC 4512 schema definition strings.
package schema

import "strings"

// SingleValue reports whether an attributeType definition carries the
// SINGLE-VALUE flag — i.e. replacing its value is all `set` can ever do.
//
// An attribute without the flag is multi-valued, including one that currently
// holds a single value: the count in an entry says nothing about the schema.
//
// SINGLE-VALUE is read from the definition itself and never inherited through
// SUP: RFC 4512 lists it as a flag of the definition, and slapd's own
// `member SUP distinguishedName` is multi-valued while its supertype is too.
func SingleValue(def string) bool { return hasFlag(def, "SINGLE-VALUE") }

// hasFlag reports whether def carries flag as a bare token. Quoted strings are
// skipped: a `DESC 'SINGLE-VALUE, historically'` must not read as the flag.
func hasFlag(def, flag string) bool {
	var bare strings.Builder
	inQuote := false
	for i := range len(def) {
		switch c := def[i]; {
		case c == '\'':
			inQuote = !inQuote
			bare.WriteByte(' ') // keep the token boundary the quote provided
		case inQuote:
		default:
			bare.WriteByte(c)
		}
	}
	for _, f := range strings.Fields(bare.String()) {
		if strings.Trim(f, "()") == flag {
			return true
		}
	}
	return false
}

// Names extracts the NAME value(s) from an objectClass/attributeType definition,
// handling both `NAME 'x'` and `NAME ( 'x' 'y' )`.
func Names(def string) []string {
	i := strings.Index(def, "NAME")
	if i < 0 {
		return nil
	}
	s := def[i+4:]
	var names []string
	inParen := false
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ")
		switch {
		case strings.HasPrefix(s, "("):
			inParen, s = true, s[1:]
		case strings.HasPrefix(s, ")"):
			return names
		case strings.HasPrefix(s, "'"):
			end := strings.Index(s[1:], "'")
			if end < 0 {
				return names
			}
			names = append(names, s[1:1+end])
			s = s[1+end+1:]
			if !inParen {
				return names
			}
		default:
			return names
		}
	}
	return names
}

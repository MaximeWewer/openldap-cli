// Package schema parses RFC 4512 schema definition strings.
package schema

import "strings"

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

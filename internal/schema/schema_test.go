package schema

import (
	"reflect"
	"testing"
)

func TestNames(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"( 2.5.6.6 NAME 'person' DESC 'x' SUP top STRUCTURAL )", []string{"person"}},
		{"( 1.2 NAME ( 'cn' 'commonName' ) SUP name )", []string{"cn", "commonName"}},
		{"( 1.2 DESC 'no name here' )", nil},
		{"{0}( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL )", []string{"inetOrgPerson"}},
	}
	for _, c := range cases {
		got := Names(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Names(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The definitions below are verbatim from a live OpenLDAP 2.6 subschema: what
// this parser has to survive is the server's spelling, not a tidied-up one.
func TestSingleValue(t *testing.T) {
	cases := []struct {
		def  string
		want bool
	}{
		// the ones the replace guard hinges on: no SINGLE-VALUE => multi-valued,
		// however few values an entry happens to hold
		{"( 1.3.6.1.4.1.4203.1.12.2.3.0.1 NAME 'olcAccess' DESC 'Access Control List' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )", false},
		{"( 1.3.6.1.4.1.4203.1.12.2.3.0.4 NAME 'olcLimits' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORDERED 'VALUES' )", false},
		{"( 1.3.6.1.4.1.4203.1.12.2.3.2.0.2 NAME 'olcDbIndex' DESC 'Attribute index parameters' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", false},
		// SUP without the flag stays multi-valued — the flag is not inherited
		{"( 2.5.4.31 NAME 'member' DESC 'RFC2256: member of a group' SUP distinguishedName )", false},

		{"( 1.3.6.1.4.1.4203.1.12.2.3.2.1.14 NAME 'olcDbMaxSize' DESC 'Maximum size of DB in bytes' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )", true},
		{"( 2.16.840.1.113730.3.1.241 NAME 'displayName' DESC 'RFC2798: preferred name to be used when displaying entries' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )", true},
		{"( 1.3.6.1.4.1.42.2.27.8.1.23 NAME 'pwdPolicySubentry' DESC 'The pwdPolicy subentry in effect for this object' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE USAGE directoryOperation )", true},

		// the flag named inside a quoted string is prose, not the flag
		{"( 1.2 NAME 'x' DESC 'was SINGLE-VALUE before v2' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", false},
		// ...and a trailing paren must not hide it
		{"( 1.2 NAME 'x' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE)", true},
	}
	for _, c := range cases {
		if got := SingleValue(c.def); got != c.want {
			t.Errorf("SingleValue(%v) = %v, want %v\n  %s", Names(c.def), got, c.want, c.def)
		}
	}
}

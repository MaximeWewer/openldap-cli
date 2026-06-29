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

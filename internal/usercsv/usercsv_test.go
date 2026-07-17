package usercsv

import (
	"reflect"
	"testing"
)

func TestField(t *testing.T) {
	for in, want := range map[string]string{
		"login": Login, "uid": Login, "user": Login, "username": Login,
		"firstname.lastname": Login,
		"UID":                Login, // headers are written by humans
		"  mail  ":           Mail,
		"group":              Group,
		"cn":                 CN,
		"sn":                 SN,
		"givenName":          GivenName,
		"givenname":          GivenName,
		"displayName":        DisplayName,
		"userPassword":       Password,
		"telephoneNumber":    "", // not something import knows how to place
		"":                   "",
	} {
		if got := Field(in); got != want {
			t.Errorf("Field(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeaderReadsExportBack(t *testing.T) {
	// verbatim what `users export` writes: the layout that used to be misread
	got := Header([]string{"uid", "cn", "sn", "givenName", "displayName", "mail"})
	want := map[string]int{Login: 0, CN: 1, SN: 2, GivenName: 3, DisplayName: 4, Mail: 5}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Header(export) =\n  %v\nwant\n  %v", got, want)
	}

	// ...and with --with-hash
	got = Header([]string{"uid", "cn", "sn", "givenName", "displayName", "mail", "userPassword"})
	if got[Password] != 6 {
		t.Errorf("userPassword column = %d, want 6", got[Password])
	}
}

func TestHeaderIsOrderIndependent(t *testing.T) {
	got := Header([]string{"login", "mail", "group"})
	want := map[string]int{Login: 0, Mail: 1, Group: 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Header = %v, want %v", got, want)
	}
	// the same fields, reversed, must map to their own columns — reading a
	// header positionally would defeat the whole point
	got = Header([]string{"login", "group", "mail"})
	if got[Mail] != 2 || got[Group] != 1 {
		t.Errorf("Header = %v", got)
	}
}

func TestHeaderIgnoresColumnsItCannotPlace(t *testing.T) {
	got := Header([]string{"uid", "department", "mail"})
	want := map[string]int{Login: 0, Mail: 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Header = %v, want %v", got, want)
	}
}

func TestHeaderDetection(t *testing.T) {
	// data rows must NOT be eaten as headers
	for _, row := range [][]string{
		{"toto.titi", "devs", "toto@x.org"},
		{"e2edemo1"},
		{},
		{"mail", "group"}, // no login column first => data, however it reads
	} {
		if h := Header(row); h != nil {
			t.Errorf("Header(%v) = %v, want nil (it is data)", row, h)
		}
	}
	// a duplicate field keeps the first column rather than letting order decide
	if got := Header([]string{"login", "mail", "mail"}); got[Mail] != 1 {
		t.Errorf("duplicate mail column = %d, want 1", got[Mail])
	}
}

func TestCell(t *testing.T) {
	row := []string{"toto.titi", "devs", " toto@x.org "}
	cols := map[string]int{Login: 0, Group: 1, Mail: 2}
	if got := Cell(row, cols, Mail); got != "toto@x.org" {
		t.Errorf("Cell(mail) = %q", got)
	}
	// a field the file does not carry, and a row shorter than the header
	if got := Cell(row, cols, SN); got != "" {
		t.Errorf("Cell(sn) = %q, want empty", got)
	}
	if got := Cell([]string{"toto.titi"}, cols, Mail); got != "" {
		t.Errorf("Cell(short row) = %q, want empty", got)
	}
}

func TestPositionalIsTheOldFormat(t *testing.T) {
	// files written for the headerless layout must keep importing the same way
	row := []string{"toto.titi", "devs", "toto@x.org"}
	if got := Cell(row, Positional, Login); got != "toto.titi" {
		t.Errorf("login = %q", got)
	}
	if got := Cell(row, Positional, Group); got != "devs" {
		t.Errorf("group = %q", got)
	}
	if got := Cell(row, Positional, Mail); got != "toto@x.org" {
		t.Errorf("mail = %q", got)
	}
	// and it carries nothing else, so the rest stays derived
	if got := Cell(row, Positional, SN); got != "" {
		t.Errorf("sn = %q, want empty", got)
	}
}

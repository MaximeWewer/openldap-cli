// Package usercsv maps the columns of a user CSV onto the fields an import
// understands.
//
// There were two CSV layouts in this tool and nothing connected them: `users
// export` wrote uid,cn,sn,givenName,displayName,mail, while `users import` read
// column 0 as the login, 1 as a GROUP and 2 as a mail override. Feeding an
// export back in — the obvious migration move — therefore put `cn` where the
// group goes and `sn` where the mail goes, and since `mail` is an IA5String with
// no format check, slapd accepted `mail: Titi` on every user and the import
// reported success.
//
// So columns are read by NAME off the header row. A file with no header keeps
// the documented positional layout, which is the only reading that cannot break
// files written for the old format.
package usercsv

import "strings"

// Fields an import understands. Everything not named is derived from the login.
const (
	Login       = "login"
	Group       = "group"
	Mail        = "mail"
	CN          = "cn"
	SN          = "sn"
	GivenName   = "givenName"
	DisplayName = "displayName"
	Password    = "userPassword"
)

// Field maps a header cell onto the field it feeds, or "" if unrecognized.
//
// `uid` maps to the login because that is what `users export` calls it: without
// that one alias an export still would not read back.
func Field(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "login", "uid", "firstname.lastname", "user", "username":
		return Login
	case "group":
		return Group
	case "mail":
		return Mail
	case "cn":
		return CN
	case "sn":
		return SN
	case "givenname":
		return GivenName
	case "displayname":
		return DisplayName
	case "userpassword":
		return Password
	}
	return ""
}

// Positional is the layout of a headerless file: the documented
// login[,group][,mail] form.
var Positional = map[string]int{Login: 0, Group: 1, Mail: 2}

// Header maps a row to field -> column index, or nil when the row is data.
//
// A row counts as a header only when its first cell names a login column. That
// is the one column every layout has, and requiring it keeps a data row from
// being eaten as a header — `mail,group` is a plausible pair of logins.
//
// A field named twice keeps its first column: a duplicate is a broken file, and
// silently preferring the last one would make which value wins depend on column
// order.
func Header(row []string) map[string]int {
	if len(row) == 0 || Field(row[0]) != Login {
		return nil
	}
	cols := map[string]int{}
	for i, cell := range row {
		f := Field(cell)
		if f == "" {
			continue
		}
		if _, dup := cols[f]; !dup {
			cols[f] = i
		}
	}
	return cols
}

// Cell returns the trimmed value of a mapped column, or "" when the file does
// not carry it (or the row is short).
func Cell(row []string, cols map[string]int, field string) string {
	i, ok := cols[field]
	if !ok || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}

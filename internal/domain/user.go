// Package domain holds your org-specific naming + schema conventions.
//
// >>> THIS IS THE FILE YOU ADAPT. <<<
// Attribute derivation, objectClasses, and DN layout live here so the rest of
// the CLI stays generic. Change ParseUser / AddRequest to match your directory.
package domain

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/dn"
)

// Posix carries optional posixAccount attributes for a user.
type Posix struct {
	UIDNumber int
	GIDNumber int
	Home      string // default /home/<login>
	Shell     string // default /bin/bash
}

// User is a person derived from the `firstname.lastname` login convention.
type User struct {
	UID         string // login, e.g. toto.titi
	FirstName   string // toto
	LastName    string // titi
	CN          string // Toto Titi
	SN          string // Titi
	GivenName   string // Toto
	DisplayName string // Toto Titi
	Mail        string // toto.titi@<mailDomain>
}

// ParseUser turns a `firstname.lastname` login into a fully derived User.
// Adapt the derivation rules here for your org.
func ParseUser(login, mailDomain string) (*User, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	if login == "" {
		return nil, fmt.Errorf("empty login")
	}
	// cn is the RDN value, matching the directory's cn=<login> convention.
	u := &User{UID: login, CN: login}
	if mailDomain != "" {
		u.Mail = login + "@" + mailDomain
	}

	if strings.Contains(login, ".") {
		// firstname.lastname -> derive given/sn/displayName.
		first, last, _ := strings.Cut(login, ".")
		if first == "" || last == "" {
			return nil, fmt.Errorf("login %q has a '.' but isn't firstname.lastname", login)
		}
		gn, sn := title(first), title(last)
		u.FirstName, u.LastName = first, last
		u.GivenName, u.SN = gn, sn
		u.DisplayName = gn + " " + sn
	} else {
		// plain login (e.g. demo1, test45) -> minimal: sn/cn required by the schema.
		u.SN = login
		u.DisplayName = login
	}
	return u, nil
}

// DN builds the entry DN: cn=<login>,<userOU>,<baseDN>.
func (u *User) DN(userOU, baseDN string) string {
	// the login is text: a `,` or `+` in it would become DN syntax
	return dn.Join("cn="+dn.EscapeValue(u.UID), userOU, baseDN)
}

// Attr is one attribute and its values.
type Attr struct {
	Name   string
	Values []string
}

// Attributes returns the derived/core attributes for this user (no password).
// Values that can be computed are filled; the rest are simply omitted. This is
// the single place to adapt which attributes the CLI derives.
func (u *User) Attributes(posix *Posix) []Attr {
	oc := []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
	if posix != nil {
		oc = append(oc, "posixAccount")
	}
	attrs := []Attr{
		{"objectClass", oc},
		{"uid", []string{u.UID}},
		{"cn", []string{u.CN}},
		{"sn", []string{u.SN}},
	}
	// only emit optional attrs when set (empty LDAP values are rejected)
	if u.GivenName != "" {
		attrs = append(attrs, Attr{"givenName", []string{u.GivenName}})
	}
	if u.DisplayName != "" {
		attrs = append(attrs, Attr{"displayName", []string{u.DisplayName}})
	}
	if u.Mail != "" {
		attrs = append(attrs, Attr{"mail", []string{u.Mail}})
	}
	if posix != nil {
		home := posix.Home
		if home == "" {
			home = "/home/" + u.UID
		}
		shell := posix.Shell
		if shell == "" {
			shell = "/bin/bash"
		}
		attrs = append(attrs,
			Attr{"uidNumber", []string{strconv.Itoa(posix.UIDNumber)}},
			Attr{"gidNumber", []string{strconv.Itoa(posix.GIDNumber)}},
			Attr{"homeDirectory", []string{home}},
			Attr{"loginShell", []string{shell}},
		)
	}
	return attrs
}

// AttributeMap returns the derived attributes as a name->values map, ready for
// ldapx.AddEntry. password and posix are optional.
func (u *User) AttributeMap(password string, posix *Posix) map[string][]string {
	m := map[string][]string{}
	for _, a := range u.Attributes(posix) {
		m[a.Name] = a.Values
	}
	if password != "" {
		// Server should hash this (configure OpenLDAP password-hash, or set the
		// password afterwards via a Password Modify extended op).
		m["userPassword"] = []string{password}
	}
	return m
}

// title upper-cases the first rune, ASCII-simple on purpose. Adapt if you need
// unicode-aware casing (golang.org/x/text/cases).
func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

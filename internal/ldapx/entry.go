package ldapx

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Entry is a directory entry, decoupled from the underlying LDAP library so
// callers never import go-ldap.
//
// Attribute lookups are case-insensitive, as LDAP attribute descriptions are: a
// server may answer "objectclass" where the request said "objectClass", and an
// exact-match map would then find nothing for a value that is right there.
type Entry struct {
	DN    string
	names []string            // as the server spelled them, in response order
	attrs map[string][]string // keyed by lowercase name
}

func newEntry(e *ldap.Entry) *Entry {
	out := &Entry{DN: e.DN, attrs: make(map[string][]string, len(e.Attributes))}
	for _, a := range e.Attributes {
		out.names = append(out.names, a.Name)
		out.attrs[strings.ToLower(a.Name)] = a.Values
	}
	return out
}

func newEntries(es []*ldap.Entry) []*Entry {
	out := make([]*Entry, len(es))
	for i, e := range es {
		out[i] = newEntry(e)
	}
	return out
}

// Get returns the first value of name, or "".
func (e *Entry) Get(name string) string {
	if v := e.attrs[strings.ToLower(name)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// GetAll returns all values of name.
func (e *Entry) GetAll(name string) []string { return e.attrs[strings.ToLower(name)] }

// Names returns the attribute names in server order.
func (e *Entry) Names() []string { return e.names }

// Scope selects search depth.
type Scope int

const (
	ScopeBase Scope = iota
	ScopeOne
	ScopeSub
)

func (s Scope) ldap() int {
	switch s {
	case ScopeBase:
		return ldap.ScopeBaseObject
	case ScopeOne:
		return ldap.ScopeSingleLevel
	default:
		return ldap.ScopeWholeSubtree
	}
}

// ModOp is the kind of a single attribute modification.
type ModOp int

const (
	ModAdd ModOp = iota
	ModReplace
	ModDelete
)

// Mod is one attribute modification (nil Values with ModDelete drops the attr).
type Mod struct {
	Op     ModOp
	Name   string
	Values []string
}

// EscapeFilter escapes a value for safe interpolation into an LDAP filter.
func EscapeFilter(s string) string { return ldap.EscapeFilter(s) }

// IsNoSuchAttribute reports whether err is LDAP "no such attribute" (code 16).
func IsNoSuchAttribute(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute)
}

// IsConstraintViolation reports whether err is LDAP "constraint violation"
// (code 19) — e.g. a password rejected by the quality policy.
func IsConstraintViolation(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation)
}

// IsNoSuchObject reports whether err is LDAP "no such object" (code 32) — the
// entry is genuinely absent, as opposed to unreadable by this bind.
func IsNoSuchObject(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject)
}

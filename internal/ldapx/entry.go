package ldapx

import "github.com/go-ldap/ldap/v3"

// Entry is a directory entry, decoupled from the underlying LDAP library so
// callers never import go-ldap.
type Entry struct {
	DN    string
	names []string
	attrs map[string][]string
}

func newEntry(e *ldap.Entry) *Entry {
	out := &Entry{DN: e.DN, attrs: make(map[string][]string, len(e.Attributes))}
	for _, a := range e.Attributes {
		out.names = append(out.names, a.Name)
		out.attrs[a.Name] = a.Values
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
	if v := e.attrs[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// GetAll returns all values of name.
func (e *Entry) GetAll(name string) []string { return e.attrs[name] }

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

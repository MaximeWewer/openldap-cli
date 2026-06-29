package ldapx

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestEntry(t *testing.T) {
	e := newEntry(ldap.NewEntry("cn=a,dc=x", map[string][]string{
		"cn":   {"a"},
		"mail": {"a@x", "b@x"},
	}))
	if e.DN != "cn=a,dc=x" {
		t.Errorf("DN = %q", e.DN)
	}
	if e.Get("cn") != "a" {
		t.Errorf("Get(cn) = %q", e.Get("cn"))
	}
	if e.Get("missing") != "" {
		t.Errorf("Get(missing) = %q, want empty", e.Get("missing"))
	}
	if got := e.GetAll("mail"); len(got) != 2 {
		t.Errorf("GetAll(mail) = %v", got)
	}
	names := e.Names()
	if len(names) != 2 {
		t.Errorf("Names = %v", names)
	}
}

func TestScopeMapping(t *testing.T) {
	cases := map[Scope]int{
		ScopeBase: ldap.ScopeBaseObject,
		ScopeOne:  ldap.ScopeSingleLevel,
		ScopeSub:  ldap.ScopeWholeSubtree,
	}
	for s, want := range cases {
		if got := s.ldap(); got != want {
			t.Errorf("Scope(%d).ldap() = %d, want %d", s, got, want)
		}
	}
}

func TestEscapeFilter(t *testing.T) {
	if got := EscapeFilter("a)b*"); got != ldap.EscapeFilter("a)b*") {
		t.Errorf("EscapeFilter mismatch: %q", got)
	}
}

func TestIsNoSuchAttribute(t *testing.T) {
	noSuch := &ldap.Error{ResultCode: ldap.LDAPResultNoSuchAttribute, Err: errors.New("x")}
	other := &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject, Err: errors.New("x")}
	if !IsNoSuchAttribute(noSuch) {
		t.Error("expected true for no-such-attribute")
	}
	if IsNoSuchAttribute(other) {
		t.Error("expected false for other code")
	}
	if IsNoSuchAttribute(nil) {
		t.Error("expected false for nil")
	}
}

package ldapx

import (
	"errors"
	"os"
	"path/filepath"
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

func TestEntryLookupIsCaseInsensitive(t *testing.T) {
	// the server picks the spelling it answers with; callers ask in whatever
	// case reads best, and both have to find the same values
	e := newEntry(&ldap.Entry{
		DN: "cn=x,dc=e",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectclass", Values: []string{"top", "person"}},
			{Name: "CN", Values: []string{"x"}},
		},
	})
	for _, name := range []string{"objectClass", "objectclass", "OBJECTCLASS"} {
		if got := e.GetAll(name); len(got) != 2 {
			t.Errorf("GetAll(%q) = %v, want 2 values", name, got)
		}
	}
	if got := e.Get("cn"); got != "x" {
		t.Errorf(`Get("cn") = %q, want "x"`, got)
	}
	// Names keeps the server's own spelling, so output shows what it sent
	if names := e.Names(); names[0] != "objectclass" || names[1] != "CN" {
		t.Errorf("Names() = %v, want the server spelling", names)
	}
}

func TestCAPoolRejectsWhatIsNotATrustAnchor(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a ca_file that loads nothing must fail loudly: silently falling back to
	// the system roots would verify against anchors the operator did not choose
	if _, err := caPool(junk); err == nil {
		t.Error("caPool accepted a file holding no PEM certificate")
	}
	if _, err := caPool(filepath.Join(dir, "absent.pem")); err == nil {
		t.Error("caPool accepted a missing file")
	}
}

func TestGetAllOptIgnoresAttributeOptions(t *testing.T) {
	// servers answer a cACertificate request as cACertificate;binary, which an
	// exact lookup misses - the certificate then reads as simply absent
	e := newEntry(&ldap.Entry{
		DN: "cn=ca,dc=e",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cACertificate;binary", Values: []string{"der-bytes"}},
			{Name: "cn", Values: []string{"ca"}},
		},
	})
	if got := e.GetAllOpt("cACertificate"); len(got) != 1 || got[0] != "der-bytes" {
		t.Errorf("GetAllOpt(cACertificate) = %v, want the ;binary values", got)
	}
	// an exact match still wins, and an absent attribute stays absent
	if got := e.GetAllOpt("cn"); len(got) != 1 || got[0] != "ca" {
		t.Errorf("GetAllOpt(cn) = %v", got)
	}
	if got := e.GetAllOpt("userCertificate"); got != nil {
		t.Errorf("GetAllOpt invented values: %v", got)
	}
}

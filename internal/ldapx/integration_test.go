//go:build integration

// Integration tests for the ldapx façade against the tests/ OpenLDAP.
// Run with: make integration   (after make test-up). Skipped if unreachable.
package ldapx_test

import (
	"strings"
	"testing"

	"github.com/MaximeWewer/openldap-cli/internal/acl"
	"github.com/MaximeWewer/openldap-cli/internal/config"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

func dataClient(t *testing.T) *ldapx.Client {
	t.Helper()
	c, err := ldapx.Connect(&config.Profile{
		URL: "ldap://localhost:389", BaseDN: "dc=example,dc=org",
		BindDN: "cn=admin,ou=users,dc=example,dc=org", BindPW: "adminpassword",
		UserOU: "ou=users", GroupOU: "ou=groups",
	})
	if err != nil {
		t.Skipf("test ldap not available: %v", err)
	}
	return c
}

func TestUserLifecycleIntegration(t *testing.T) {
	c := dataClient(t)
	defer c.Close()

	dn := "cn=itest.user,ou=users,dc=example,dc=org"
	_ = c.Delete(dn) // remove any leftover from a previous run

	if err := c.AddEntry(dn, map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"cn":          {"itest.user"},
		"sn":          {"User"},
		"uid":         {"itest.user"},
	}); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	defer c.Delete(dn)

	e, err := c.FindUser("itest.user", []string{"uid", "sn"})
	if err != nil {
		t.Fatalf("FindUser: %v", err)
	}
	if e.DN != dn || e.Get("sn") != "User" {
		t.Errorf("found %+v", e)
	}

	if err := c.Modify(dn, []ldapx.Mod{{Op: ldapx.ModReplace, Name: "sn", Values: []string{"Changed"}}}); err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if e2, _ := c.FindUser("itest.user", []string{"sn"}); e2.Get("sn") != "Changed" {
		t.Errorf("sn after modify = %q", e2.Get("sn"))
	}

	if es, err := c.Search(c.UserBase(), "(uid=itest.user)", []string{"uid"}); err != nil || len(es) != 1 {
		t.Fatalf("Search = %v, %v", es, err)
	}

	if err := c.Delete(dn); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.FindUser("itest.user", nil); err == nil {
		t.Error("expected not-found after delete")
	}
}

func TestACLRoundtripIntegration(t *testing.T) {
	c, err := ldapx.Connect(&config.Profile{
		URL: "ldap://localhost:389", BaseDN: "dc=example,dc=org",
		BindDN: "cn=adminconfig,cn=config", BindPW: "configpassword",
	})
	if err != nil {
		t.Skipf("config bind unavailable: %v", err)
	}
	defer c.Close()

	const (
		db  = "olcDatabase={1}mdb,cn=config"
		svc = "cn=itest.svc,ou=service-accounts,dc=example,dc=org"
	)
	who := acl.DNWho(svc)
	rule, _, err := c.InjectAccess(db, acl.InjectOpts{
		Target: "ou=itest,dc=example,dc=org", Who: who, Access: "read", At: -1,
	})
	if err != nil {
		t.Fatalf("InjectAccess: %v", err)
	}
	if rule == "" {
		t.Error("empty resulting rule")
	}
	// the injected rule is `by <who> read by * break`: revoking its only
	// grantee must drop the whole rule, not leave a clauseless one behind
	// (slapd would reject that and fail the revoke).
	removed, dropped, err := c.RemoveAccessGrantee(db, who)
	if err != nil {
		t.Fatalf("RemoveAccessGrantee: %v", err)
	}
	if removed < 1 || dropped < 1 {
		t.Errorf("removed = %d, dropped = %d, want >= 1 each", removed, dropped)
	}
	e, err := c.ReadEntry(db, []string{"olcAccess"})
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	for _, v := range e.GetAll("olcAccess") {
		if strings.Contains(v, "ou=itest,dc=example,dc=org") {
			t.Errorf("revoke left the rule behind: %s", v)
		}
	}
}

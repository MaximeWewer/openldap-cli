//go:build e2e

// End-to-end CLI tests: build the real binary and drive every command group
// against the tests/ OpenLDAP. Run with `make e2e` (after `make test-up`).
// Skipped automatically if the directory is unreachable.
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var binPath string

const (
	admin = "cn=admin,ou=users,dc=example,dc=org"
	root  = "cn=admin,dc=example,dc=org" // rootDN, for ou=policies / cn=config writes
	adPW  = "adminpassword"
	rtPW  = "rootpassword"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "openldap-cli-e2e")
	if err != nil {
		panic(err)
	}
	binPath = dir + "/openldap-cli"
	build := exec.Command("go", "build", "-o", binPath, "../cmd/openldap-cli")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func env(bindDN, bindPW string) []string {
	return append(os.Environ(),
		"LDAP_URL=ldap://localhost:389",
		"LDAP_BASE_DN=dc=example,dc=org",
		"LDAP_BIND_DN="+bindDN,
		"LDAP_BIND_PW="+bindPW,
		"LDAP_USER_OU=ou=users",
		"LDAP_GROUP_OU=ou=groups",
		"LDAP_POLICY_OU=ou=policies",
		"LDAP_MAIL_DOMAIN=example.org",
		"LDAP_CONFIG_BIND_DN=cn=adminconfig,cn=config",
		"LDAP_CONFIG_BIND_PW=configpassword",
	)
}

// try runs the binary without failing the test (used for setup/cleanup).
func try(bindDN, bindPW string, args ...string) (stdout, stderr string, err error) {
	full := append([]string{"--config", "/nonexistent-e2e.yaml", "--log-level", "error"}, args...)
	cmd := exec.Command(binPath, full...)
	cmd.Env = env(bindDN, bindPW)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return so.String(), se.String(), err
}

// run runs the binary and fails the test on a non-zero exit.
func run(t *testing.T, bindDN, bindPW string, args ...string) string {
	t.Helper()
	so, se, err := try(bindDN, bindPW, args...)
	if err != nil {
		t.Fatalf("%v\n  exit: %v\n  stderr: %s", args, err, se)
	}
	return so
}

func has(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Errorf("missing %q in:\n%s", sub, s)
	}
}

func cleanup() {
	// delete each individually — a single missing login would abort a variadic
	// `users delete`, leaving the rest behind.
	for _, u := range []string{"e2e.alpha", "e2e.beta", "e2e.gamma", "e2e.delta", "e2e.epsilon", "e2e.bak"} {
		try(admin, adPW, "user", "delete", u)
	}
	try(admin, adPW, "group", "delete", "e2e.devs")
	try(admin, adPW, "svc", "delete", "e2e.svc")
	try(admin, adPW, "ou", "delete", "e2e.unit", "--parent", "ou=users,dc=example,dc=org")
	try(root, rtPW, "ppolicy", "delete", "e2e.pol")
	for _, d := range []string{"cn=e2e.dev,ou=users,dc=example,dc=org", "cn=e2e.dev2,ou=users,dc=example,dc=org"} {
		try(admin, adPW, "entry", "delete", d)
	}
}

func TestCLI(t *testing.T) {
	if _, _, err := try(admin, adPW, "whoami"); err != nil {
		t.Skipf("test ldap not available (run `make test-up`): %v", err)
	}
	cleanup()
	t.Cleanup(cleanup)

	t.Run("general", func(t *testing.T) {
		has(t, run(t, admin, adPW, "whoami"), "cn=admin,ou=users")
		has(t, run(t, admin, adPW, "version"), "openldap-cli")
		has(t, run(t, admin, adPW, "search", "(uid=user1.name)", "--attrs", "uid"), "user1.name")
		has(t, run(t, admin, adPW, "search", "(uid=user1.name)", "--operational"), "entryUUID")
		// escape hatch into cn=config via the config bind
		has(t, run(t, admin, adPW, "search", "(objectClass=olcModuleList)", "--base", "cn=config", "--attrs", "olcModuleLoad", "--config-bind"), "olcModuleLoad")
	})

	t.Run("user", func(t *testing.T) {
		has(t, run(t, admin, adPW, "user", "add", "e2e.alpha", "--no-password", "--set", "title=Engineer", "--set", "bogus=x"),
			`attribute "bogus" not in schema`)
		has(t, run(t, admin, adPW, "user", "info", "e2e.alpha"), "e2e.alpha")

		js := run(t, admin, adPW, "-o", "json", "user", "info", "e2e.alpha")
		var info map[string]any
		if err := json.Unmarshal([]byte(js), &info); err != nil {
			t.Fatalf("json info: %v\n%s", err, js)
		}
		if info["uid"] != "e2e.alpha" {
			t.Errorf("json uid = %v", info["uid"])
		}

		run(t, admin, adPW, "user", "set", "e2e.alpha", "description", "Pioneer")
		run(t, admin, adPW, "user", "passwd", "e2e.alpha", "--password", "LongPassword12345")
		run(t, admin, adPW, "user", "force-reset", "e2e.alpha")
		has(t, run(t, admin, adPW, "user", "info", "e2e.alpha"), "mustChange")
		run(t, admin, adPW, "user", "force-reset", "e2e.alpha", "--clear")
		has(t, run(t, admin, adPW, "user", "rename", "e2e.alpha", "e2e.beta"), "e2e.beta")
		has(t, run(t, admin, adPW, "user", "unlock", "e2e.beta"), "unlocked")

		// plain login (no dot) is accepted -> uid/cn/sn = login
		has(t, run(t, admin, adPW, "user", "add", "e2edemo1", "--no-password"), "cn=e2edemo1,ou=users")
		has(t, run(t, admin, adPW, "user", "info", "e2edemo1"), "e2edemo1")
		run(t, admin, adPW, "user", "delete", "e2edemo1")
	})

	t.Run("group", func(t *testing.T) {
		has(t, run(t, admin, adPW, "group", "create", "e2e.devs", "--member", "e2e.beta"), "created")
		has(t, run(t, admin, adPW, "group", "info", "e2e.devs"), "e2e.beta")
		run(t, admin, adPW, "group", "add-member", "e2e.devs", "user1.name")
		has(t, run(t, admin, adPW, "groups", "list"), "e2e.devs")
		run(t, admin, adPW, "group", "remove-member", "e2e.devs", "user1.name")
	})

	t.Run("bulk", func(t *testing.T) {
		csv := tmpFile(t, "login\ne2e.gamma\ne2e.delta\n")
		has(t, run(t, admin, adPW, "users", "import", csv), "imported 2")
		has(t, run(t, admin, adPW, "users", "list"), "e2e.gamma")
		run(t, admin, adPW, "users", "set", "title", "Temp", "e2e.gamma", "e2e.delta")
		has(t, run(t, admin, adPW, "users", "passwd", "e2e.gamma"), "e2e.gamma")
		has(t, run(t, admin, adPW, "users", "export"), "e2e.beta")
		has(t, run(t, admin, adPW, "users", "export", "--ldif"), "dn: cn=e2e.beta")

		ldifFile := tmpFile(t, "dn: cn=e2e.epsilon,ou=users,dc=example,dc=org\nobjectClass: inetOrgPerson\ncn: e2e.epsilon\nsn: Eps\n")
		has(t, run(t, admin, adPW, "import-ldif", ldifFile), "imported 1")
		has(t, run(t, admin, adPW, "user", "info", "e2e.epsilon"), "e2e.epsilon")

		// partial bulk delete: one existing + one missing -> per-item, not abort
		out := run(t, admin, adPW, "users", "delete", "e2e.delta", "e2e.ghost.missing")
		has(t, out, "1 ok, 1 failed")
		has(t, out, "e2e.ghost.missing")
	})

	t.Run("svc", func(t *testing.T) {
		has(t, run(t, admin, adPW, "svc", "add", "e2e.svc", "--subtree", "ou=users,dc=example,dc=org", "--access", "read"), "created")
		has(t, run(t, admin, adPW, "svcs", "list"), "e2e.svc")
		has(t, run(t, admin, adPW, "svc", "info", "e2e.svc"), "e2e.svc")
		has(t, run(t, admin, adPW, "svc", "delete", "e2e.svc"), "removed 1 ACL clause")
	})

	t.Run("ou", func(t *testing.T) {
		parent := "ou=users,dc=example,dc=org"
		has(t, run(t, admin, adPW, "ou", "create", "e2e.unit", "--parent", parent), "created")
		has(t, run(t, admin, adPW, "ou", "list"), "e2e.unit")
		run(t, admin, adPW, "ou", "delete", "e2e.unit", "--parent", parent)
	})

	t.Run("ppolicy", func(t *testing.T) {
		has(t, run(t, root, rtPW, "ppolicy", "set", "e2e.pol", "--min-length", "12", "--max-failure", "3"), "created")
		has(t, run(t, admin, adPW, "ppolicy", "list"), "e2e.pol")
		has(t, run(t, admin, adPW, "ppolicy", "show", "e2e.pol"), "pwdMinLength")
		run(t, admin, adPW, "ppolicy", "assign", "e2e.beta", "e2e.pol")
		has(t, run(t, admin, adPW, "user", "info", "e2e.beta"), "e2e.pol")
		run(t, admin, adPW, "ppolicy", "assign", "e2e.beta", "--clear")
		run(t, root, rtPW, "ppolicy", "delete", "e2e.pol")
	})

	t.Run("config", func(t *testing.T) {
		has(t, run(t, admin, adPW, "config", "db", "list"), "olcDatabase")
		// resize: only exercise arg parsing/wiring — a live olcDbMaxSize remap can
		// intermittently disrupt/restart slapd (racy with active txns), which would
		// flake later subtests. The bad-unit path mutates nothing.
		if _, se, rerr := try(root, rtPW, "config", "db", "resize", "olcDatabase={1}mdb,cn=config", "4Zorks"); rerr == nil || !strings.Contains(se, "unknown size unit") {
			t.Errorf("config db resize bad unit: err=%v stderr=%s", rerr, se)
		}
		has(t, run(t, admin, adPW, "config", "overlay", "list"), "olcOverlay")
		has(t, run(t, admin, adPW, "config", "acl", "list", "olcDatabase={1}mdb,cn=config"), "olcAccess")
		// reorder an olcAccess rule and put it back (live, no restart)
		db := "olcDatabase={1}mdb,cn=config"
		has(t, run(t, root, rtPW, "config", "acl", "move", db, "0", "1"), "moved olcAccess {0} to {1}")
		run(t, root, rtPW, "config", "acl", "move", db, "1", "0")
		// grant a group read on a subtree (by group.exact clause), then revoke
		has(t, run(t, admin, adPW, "config", "acl", "grant", db, "ou=users,dc=example,dc=org", "--group", "e2e.devs", "--access", "read"),
			`granted read to group.exact="cn=e2e.devs`)
		has(t, run(t, admin, adPW, "config", "acl", "list", db), `by group.exact="cn=e2e.devs`)
		has(t, run(t, admin, adPW, "config", "acl", "revoke", db, "--group", "e2e.devs"), "revoked 1 clause")
		// the "app must search a tree and read only some entries" pattern:
		// base-scope container grant + filtered read grant, both placed by --at
		has(t, run(t, admin, adPW, "config", "acl", "grant", db, "ou=users,dc=example,dc=org",
			"--group", "e2e.devs", "--access", "search", "--scope", "base", "--at", "4"), `to dn.base="ou=users`)
		has(t, run(t, admin, adPW, "config", "acl", "grant", db, "ou=users,dc=example,dc=org",
			"--group", "e2e.devs", "--access", "read", "--at", "5",
			"--filter", "(memberOf=cn=e2e.devs,ou=groups,dc=example,dc=org)"), "filter=(memberOf=cn=e2e.devs")
		run(t, admin, adPW, "config", "acl", "revoke", db, "--group", "e2e.devs")
		has(t, run(t, admin, adPW, "config", "acl", "lint", db), "rule(s) checked")
		run(t, root, rtPW, "config", "limits", "set", "--size", "2000")
		has(t, run(t, admin, adPW, "config", "limits", "get"), "olcSizeLimit")
	})

	t.Run("schema", func(t *testing.T) {
		has(t, run(t, admin, adPW, "schema", "list-classes"), "inetOrgPerson")
		has(t, run(t, admin, adPW, "schema", "show", "inetOrgPerson"), "NAME 'inetOrgPerson'")
	})

	t.Run("ops", func(t *testing.T) {
		has(t, run(t, admin, adPW, "ops", "db-stats"), "dc=example,dc=org")
		has(t, run(t, admin, adPW, "ops", "monitor"), "connections")
		has(t, run(t, admin, adPW, "ops", "who-can-write", admin), "dn.exact")
		has(t, run(t, admin, adPW, "ops", "audit-binds", "--since", "1h"), "binds in last")
		has(t, run(t, admin, adPW, "ops", "accesslog-purge", "--dry-run"), "dry-run")
		has(t, run(t, admin, adPW, "ops", "replication"), "contextCSN")
	})

	t.Run("backup", func(t *testing.T) {
		gz := t.TempDir() + "/data.ldif.gz"

		// throwaway user -> dump -> delete -> restore from the gz -> back
		run(t, admin, adPW, "user", "add", "e2e.bak", "--password", "LongPassword12345")
		has(t, run(t, admin, adPW, "backup", "data", gz), "backed up")
		if fi, err := os.Stat(gz); err != nil || fi.Size() == 0 {
			t.Fatalf("gz not written: %v", err)
		}

		run(t, admin, adPW, "user", "delete", "e2e.bak")
		// restore binds as rootDN: the Relax control (to re-add a userPassword
		// under a strict ppolicy) is only honored for the rootDN.
		has(t, run(t, root, rtPW, "backup", "restore", gz), "imported")
		has(t, run(t, admin, adPW, "user", "info", "e2e.bak"), "e2e.bak")
	})

	t.Run("entry", func(t *testing.T) {
		dn := "cn=e2e.dev,ou=users,dc=example,dc=org"
		has(t, run(t, admin, adPW, "entry", "add", dn, "objectClass=device", "objectClass=top", "cn=e2e.dev", "serialNumber=SN1"), "added")
		has(t, run(t, admin, adPW, "entry", "get", dn, "serialNumber"), "SN1")
		run(t, admin, adPW, "entry", "set", dn, "description", "d1")
		run(t, admin, adPW, "entry", "set", dn, "description", "d2", "--add")
		got := run(t, admin, adPW, "entry", "get", dn, "description")
		has(t, got, "d1")
		has(t, got, "d2")
		run(t, admin, adPW, "entry", "set", dn, "serialNumber") // delete attr
		has(t, run(t, admin, adPW, "entry", "rename", dn, "cn=e2e.dev2"), "cn=e2e.dev2,ou=users")
		run(t, admin, adPW, "entry", "delete", "cn=e2e.dev2,ou=users,dc=example,dc=org")
		// generic escape hatch reaches cn=config with --config-bind
		has(t, run(t, admin, adPW, "entry", "get", "cn=module{0},cn=config", "olcModuleLoad", "--config-bind"), "olcModuleLoad")
	})

	t.Run("sizelimit", func(t *testing.T) {
		db := "olcDatabase={1}mdb,cn=config"
		// cap below the number of users: a naive read fails with code 4. The CLI
		// must transparently lift the limit via the config bind and still return
		// everyone, then restore olcLimits.
		run(t, root, rtPW, "config", "set", db, "olcSizeLimit", "1")
		t.Cleanup(func() { try(root, rtPW, "config", "set", db, "olcSizeLimit", "500") })

		out := run(t, admin, adPW, "users", "list")
		has(t, out, "user1.name")
		has(t, out, "user2.name")

		// the temporary per-identity override must be gone afterwards
		lim := run(t, admin, adPW, "config", "limits", "get", "--db", db)
		if strings.Contains(lim, "olcLimits") && strings.Contains(lim, admin) {
			t.Errorf("temporary olcLimits not reverted:\n%s", lim)
		}
	})

	t.Run("profile", func(t *testing.T) {
		// profile commands read the (nonexistent) config file gracefully
		_, _, _ = try(admin, adPW, "profile", "current")
	})
}

func tmpFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "e2e-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

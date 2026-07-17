//go:build e2e

// End-to-end CLI tests: build the real binary and drive every command group
// against the tests/ OpenLDAP. Run with `make e2e` (after `make test-up`).
// Skipped automatically if the directory is unreachable.
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
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
	for _, u := range []string{"e2e.alpha", "e2e.beta", "e2e.gamma", "e2e.delta", "e2e.epsilon", "e2e.bak", "e2e.lockme"} {
		try(admin, adPW, "user", "delete", u)
	}
	try(admin, adPW, "group", "delete", "e2e.devs")
	try(admin, adPW, "group", "delete", "e2e.eng") // a failed rename subtest leaves this name
	try(admin, adPW, "svc", "revoke", "e2e.svc") // a failed svc subtest would leave its grants behind
	try(admin, adPW, "svc", "delete", "e2e.svc")
	for _, o := range []string{"e2e.unit", "e2e.renamed"} {
		try(admin, adPW, "entry", "delete", "cn=e2e.kid,ou="+o+",ou=users,dc=example,dc=org")
		try(admin, adPW, "ou", "delete", o, "--parent", "ou=users,dc=example,dc=org")
	}
	// --force: teardown must not be blocked by the in-use guard if a failed
	// subtest left the policy assigned to a user
	try(root, rtPW, "ppolicy", "delete", "e2e.pol", "--force")
	// a failed overlay subtest would otherwise leave it enabled
	try(admin, adPW, "config", "overlay", "disable", "constraint", "--purge")
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

	t.Run("dn-escaping", func(t *testing.T) {
		// A DN is assembled from text, so a `,` or `+` in a name used to become DN
		// syntax and slapd rejected the lot with a bare `Invalid DN Syntax`.
		// RFC 4514 escaping makes them ordinary characters.
		has(t, run(t, admin, adPW, "group", "create", "e2e,comma", "--member", "user1.name"), `cn=e2e\,comma`)
		defer try(root, rtPW, "group", "delete", "e2e,comma")
		// the value must survive the round trip, and the name must still resolve
		has(t, run(t, admin, adPW, "group", "info", "e2e,comma"), "cn: e2e,comma")

		has(t, run(t, admin, adPW, "user", "add", "e2e+plus", "--no-password"), `cn=e2e\+plus`)
		defer try(admin, adPW, "user", "delete", "e2e+plus")
		has(t, run(t, admin, adPW, "user", "info", "e2e+plus"), "e2e+plus")

		// rename and delete must reach it too (the server hands the DN back
		// hex-escaped, `\2C`, not the `\,` we sent)
		run(t, root, rtPW, "group", "rename", "e2e,comma", "e2e;semi")
		defer try(root, rtPW, "group", "delete", "e2e;semi")
		has(t, run(t, admin, adPW, "group", "info", "e2e;semi"), "cn: e2e;semi")

		// an ordinary name must come through byte-for-byte
		has(t, run(t, admin, adPW, "group", "create", "e2e.plain", "--member", "user1.name"),
			"cn=e2e.plain,ou=groups,dc=example,dc=org")
		try(root, rtPW, "group", "delete", "e2e.plain")
	})

	t.Run("wrong-type", func(t *testing.T) {
		// The typed commands only manage groupOfNames / inetOrgPerson. An entry of
		// another type is not "not found" — saying so sends the operator looking
		// for something that is right there.
		const gDN = "cn=e2e.legacy,ou=groups,dc=example,dc=org"
		const uDN = "cn=e2e.legacyuser,ou=users,dc=example,dc=org"
		run(t, root, rtPW, "entry", "add", gDN, "objectClass=top", "objectClass=groupOfUniqueNames",
			"cn=e2e.legacy", "uniqueMember=cn=user1.name,ou=users,dc=example,dc=org")
		defer try(root, rtPW, "entry", "delete", gDN)
		run(t, root, rtPW, "entry", "add", uDN, "objectClass=top", "objectClass=person",
			"cn=e2e.legacyuser", "sn=Legacy")
		defer try(root, rtPW, "entry", "delete", uDN)

		_, se, err := try(admin, adPW, "group", "info", "e2e.legacy")
		if err == nil {
			t.Error("group info on a groupOfUniqueNames unexpectedly succeeded")
		}
		for _, want := range []string{"exists (" + gDN, "groupOfUniqueNames", "not groupOfNames"} {
			if !strings.Contains(se, want) {
				t.Errorf("wrong-type group error missing %q in:\n%s", want, se)
			}
		}
		if _, se, err = try(admin, adPW, "user", "info", "e2e.legacyuser"); err == nil {
			t.Error("user info on a plain person unexpectedly succeeded")
		} else if !strings.Contains(se, "not inetOrgPerson") {
			t.Errorf("wrong-type user error unclear:\n%s", se)
		}
		// a name that really is absent still reads as absent
		if _, se, err = try(admin, adPW, "group", "info", "e2e.nosuch"); err == nil ||
			!strings.Contains(se, "not found") {
			t.Errorf("an absent group must still say not found: err=%v stderr=%s", err, se)
		}
		// The listings must own up to what their filter hides — in the RESULT, so
		// it survives -o json and a raised log level.
		has(t, run(t, admin, adPW, "groups", "list"), "not groupOfNames and are not listed")
		has(t, run(t, admin, adPW, "users", "list"), "not inetOrgPerson and are not listed")
		has(t, run(t, admin, adPW, "-o", "json", "groups", "list"), "skippedNotGroupOfNames")
	})

	t.Run("replace-guard", func(t *testing.T) {
		// `set` REPLACES: on a multi-valued attribute it drops every value not
		// passed. One `config set olcAccess '<rule>'` used to wipe every ACL on
		// the database and report success.
		db := "olcDatabase={1}mdb,cn=config"
		before := aclValues(t, db)
		_, se, err := try(root, rtPW, "config", "set", db, "olcAccess", `to dn.base="dc=example,dc=org" by * read`)
		if err == nil {
			t.Fatal("config set olcAccess: wiped the ACLs instead of refusing")
		}
		for _, want := range []string{"would delete", "config acl grant", "--force"} {
			if !strings.Contains(se, want) {
				t.Errorf("replace refusal missing %q in:\n%s", want, se)
			}
		}
		if after := aclValues(t, db); len(after) != len(before) {
			t.Fatalf("a refusal still wrote: %d rules before, %d after", len(before), len(after))
		}
		// passing every value back is a faithful rewrite, not a loss
		restoreACL(t, db, before)
		// a single-valued attribute is exactly what `set` is for
		run(t, root, rtPW, "config", "set", "olcOverlay={4}accesslog,olcDatabase={1}mdb,cn=config",
			"olcAccessLogSuccess", "TRUE")
		run(t, root, rtPW, "config", "set", "olcOverlay={4}accesslog,olcDatabase={1}mdb,cn=config",
			"olcAccessLogSuccess", "FALSE")

		// same guard on the data tree: a group's member list
		run(t, admin, adPW, "group", "create", "e2e.rg", "--member", "user1.name")
		defer try(admin, adPW, "group", "delete", "e2e.rg")
		run(t, admin, adPW, "group", "add-member", "e2e.rg", "user2.name")
		if _, se, err = try(admin, adPW, "group", "set", "e2e.rg", "member",
			"cn=user1.name,ou=users,dc=example,dc=org"); err == nil {
			t.Error("group set member: dropped a member instead of refusing")
		} else if !strings.Contains(se, "would delete 1 of them") {
			t.Errorf("member refusal unclear:\n%s", se)
		}
		// --force is the way through
		run(t, admin, adPW, "group", "set", "e2e.rg", "member",
			"cn=user1.name,ou=users,dc=example,dc=org", "--force")
	})

	t.Run("errors", func(t *testing.T) {
		// A write the ACLs don't allow must name the rootDN to use, not just
		// say 50. The seed's data admin cannot write under ou=policies.
		_, se, err := try(admin, adPW, "ppolicy", "set", "e2e.denied", "--min-length", "12")
		if err == nil {
			t.Fatal("ppolicy set as the data admin unexpectedly succeeded")
		}
		for _, want := range []string{"Insufficient Access Rights", "rootDN of dc=example,dc=org", "cn=admin,dc=example,dc=org"} {
			if !strings.Contains(se, want) {
				t.Errorf("code-50 hint missing %q in:\n%s", want, se)
			}
		}
		// A wrong password must mention that a lockout is indistinguishable,
		// since retrying is what deepens it.
		_, se, err = try("cn=user1.name,ou=users,dc=example,dc=org", "definitely-wrong", "whoami")
		if err == nil {
			t.Fatal("bind with a wrong password unexpectedly succeeded")
		}
		for _, want := range []string{"Invalid Credentials", "lockout looks identical", "user info"} {
			if !strings.Contains(se, want) {
				t.Errorf("code-49 hint missing %q in:\n%s", want, se)
			}
		}
		// ...and a real lockout, on a server that discloses it, must be named.
		ppolicyDN := "olcOverlay={2}ppolicy,olcDatabase={1}mdb,cn=config"
		run(t, root, rtPW, "config", "set", ppolicyDN, "olcPPolicyUseLockout", "TRUE")
		defer func() { // try, not run: a cleanup must not fail the test
			try(root, rtPW, "config", "set", ppolicyDN, "olcPPolicyUseLockout")
			try(root, rtPW, "user", "unlock", "e2e.lockme")
			try(admin, adPW, "user", "delete", "e2e.lockme")
		}()
		const lockPW = "e2e-lockme-password-1" // defaultppolicy: pwdMinLength = 16
		run(t, admin, adPW, "user", "add", "e2e.lockme", "--password", lockPW)
		lockDN := "cn=e2e.lockme,ou=users,dc=example,dc=org"
		for range 4 { // defaultppolicy: pwdMaxFailure = 3
			try(lockDN, "wrong-on-purpose", "whoami")
		}
		// the RIGHT password now: only the policy control can explain this
		_, se, err = try(lockDN, lockPW, "whoami")
		if err == nil {
			t.Fatal("the account did not lock; the lockout message is untested")
		}
		for _, want := range []string{"locked by the password policy", "user unlock"} {
			if !strings.Contains(se, want) {
				t.Errorf("lockout message missing %q in:\n%s", want, se)
			}
		}
	})

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
		has(t, run(t, admin, adPW, "group", "set", "e2e.devs", "description", "Core team"), "set description on")
		has(t, run(t, admin, adPW, "group", "info", "e2e.devs"), "Core team")
		has(t, run(t, admin, adPW, "group", "set", "e2e.devs", "description"), "deleted description on")
		// rename and back: members ride along, and the old cn must not linger
		has(t, run(t, admin, adPW, "group", "rename", "e2e.devs", "e2e.eng"), "cn=e2e.eng")
		has(t, run(t, admin, adPW, "group", "info", "e2e.eng"), "e2e.beta")
		if _, _, gerr := try(admin, adPW, "group", "info", "e2e.devs"); gerr == nil {
			t.Error("group info: the old name still resolves after a rename")
		}
		run(t, admin, adPW, "group", "rename", "e2e.eng", "e2e.devs")

		// a rename must carry its ACLs with it: slapd rewrites none of them, so
		// an un-repaired grant keeps naming a DN that no longer exists and
		// silently grants nothing.
		db := "olcDatabase={1}mdb,cn=config"
		run(t, admin, adPW, "config", "acl", "grant", db, "ou=service-accounts,dc=example,dc=org",
			"--group", "e2e.devs", "--access", "read")
		run(t, admin, adPW, "group", "rename", "e2e.devs", "e2e.eng")
		has(t, run(t, admin, adPW, "config", "acl", "list", db), `group.exact="cn=e2e.eng,ou=groups,dc=example,dc=org"`)
		if strings.Contains(run(t, admin, adPW, "config", "acl", "list", db), "cn=e2e.devs,ou=groups") {
			t.Error("config acl: a rule still names the old group DN after a rename")
		}
		// --no-fix-acl leaves the rule naming the old DN, on purpose
		run(t, admin, adPW, "group", "rename", "e2e.eng", "e2e.devs", "--no-fix-acl")
		has(t, run(t, admin, adPW, "config", "acl", "list", db), `group.exact="cn=e2e.eng,ou=groups,dc=example,dc=org"`)
		run(t, admin, adPW, "config", "acl", "revoke", db, "--group", "cn=e2e.eng,ou=groups,dc=example,dc=org")
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
		// grant two trees, then revoke one: the other must survive. Both of
		// ou=groups' rules are seeded, so the grant only adds clauses to them.
		run(t, admin, adPW, "svc", "grant", "e2e.svc", "--tree", "ou=groups,dc=example,dc=org")
		run(t, admin, adPW, "svc", "grant", "e2e.svc", "--tree", "ou=policies,dc=example,dc=org")
		has(t, run(t, admin, adPW, "svc", "revoke", "e2e.svc", "--tree", "ou=groups,dc=example,dc=org"),
			"on ou=groups,dc=example,dc=org")
		// scoped revoke must not touch the other tree's grant
		has(t, run(t, admin, adPW, "config", "acl", "list", "olcDatabase={1}mdb,cn=config"),
			`to dn.base="ou=policies,dc=example,dc=org" by dn.exact="cn=e2e.svc`)
		if _, se, rerr := try(admin, adPW, "svc", "revoke", "e2e.svc", "--tree", "ou=absent,dc=example,dc=org"); rerr == nil || !strings.Contains(se, "no access on ou=absent") {
			t.Errorf("svc revoke on an ungranted tree: err=%v stderr=%s", rerr, se)
		}
		// no --tree: everything the account still has (ou=policies + its own subtree)
		has(t, run(t, admin, adPW, "svc", "revoke", "e2e.svc"), "everywhere")
		has(t, run(t, admin, adPW, "svc", "delete", "e2e.svc"), "removed 0 ACL clause")
		has(t, run(t, admin, adPW, "config", "acl", "lint", "olcDatabase={1}mdb,cn=config"), "no dead or empty rules")
	})

	t.Run("ou", func(t *testing.T) {
		parent := "ou=users,dc=example,dc=org"
		has(t, run(t, admin, adPW, "ou", "create", "e2e.unit", "--parent", parent), "created")
		has(t, run(t, admin, adPW, "ou", "list"), "e2e.unit")
		has(t, run(t, admin, adPW, "ou", "info", "e2e.unit", "--parent", parent), "ou=e2e.unit,"+parent)
		has(t, run(t, admin, adPW, "ou", "set", "e2e.unit", "description", "External staff", "--parent", parent), "set description on")
		has(t, run(t, admin, adPW, "ou", "info", "e2e.unit", "--parent", parent), "External staff")
		has(t, run(t, admin, adPW, "ou", "set", "e2e.unit", "description", "--parent", parent), "deleted description on")
		// rename with a child: the child's DN must follow the new parent name
		run(t, admin, adPW, "entry", "add", "cn=e2e.kid,ou=e2e.unit,"+parent, "objectClass=device", "objectClass=top", "cn=e2e.kid")
		has(t, run(t, admin, adPW, "ou", "rename", "e2e.unit", "e2e.renamed", "--parent", parent), "ou=e2e.renamed,"+parent)
		has(t, run(t, admin, adPW, "search", "(cn=e2e.kid)"), "cn=e2e.kid,ou=e2e.renamed,"+parent)
		run(t, admin, adPW, "entry", "delete", "cn=e2e.kid,ou=e2e.renamed,"+parent)
		run(t, admin, adPW, "ou", "delete", "e2e.renamed", "--parent", parent)
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

	// A pwdPolicySubentry that does not resolve does not fall back to the
	// default: slapd applies NO policy to that user. So every path that could
	// write or strand such a reference has to refuse.
	t.Run("ppolicy-dangling", func(t *testing.T) {
		run(t, root, rtPW, "ppolicy", "set", "e2e.pol", "--min-length", "12")
		defer try(root, rtPW, "ppolicy", "delete", "e2e.pol", "--force")

		// a typo must not be written verbatim
		_, se, err := try(admin, adPW, "ppolicy", "assign", "e2e.beta", "e2e.pol.typo")
		if err == nil || !strings.Contains(se, "no password policy named") {
			t.Errorf("assign to a missing policy: err=%v stderr=%s", err, se)
		}
		has(t, se, "e2e.pol") // the refusal names the policies that do exist
		if info := run(t, admin, adPW, "user", "info", "e2e.beta"); strings.Contains(info, "typo") {
			t.Errorf("assign was refused but wrote anyway:\n%s", info)
		}

		// An entry that exists but is not a pwdPolicy lands slapd on the same
		// no-policy path (ppolicy_get fetches the subentry with an objectClass
		// filter), so existence alone is not enough — it must be refused too.
		// This one sits in the policy OU, where a name-only check would find it.
		notPol := "cn=e2e.notpol,ou=policies,dc=example,dc=org"
		run(t, root, rtPW, "entry", "add", notPol, "objectClass=top", "objectClass=applicationProcess", "cn=e2e.notpol")
		defer try(root, rtPW, "entry", "delete", notPol)
		if _, se, err := try(admin, adPW, "ppolicy", "assign", "e2e.beta", "e2e.notpol"); err == nil ||
			!strings.Contains(se, "no password policy named") {
			t.Errorf("assign to a non-policy entry in the policy OU: err=%v stderr=%s", err, se)
		}

		// --clear and a policy-name are opposite intents
		if _, se, err := try(admin, adPW, "ppolicy", "assign", "e2e.beta", "e2e.pol", "--clear"); err == nil ||
			!strings.Contains(se, "--clear takes no policy-name") {
			t.Errorf("assign --clear with a name: err=%v stderr=%s", err, se)
		}

		// deleting a policy out from under its users strands them
		run(t, admin, adPW, "ppolicy", "assign", "e2e.beta", "e2e.pol")
		_, se, err = try(root, rtPW, "ppolicy", "delete", "e2e.pol")
		if err == nil || !strings.Contains(se, "still in use") {
			t.Errorf("delete of an assigned policy: err=%v stderr=%s", err, se)
		}
		has(t, se, "cn=e2e.beta") // the refusal names who would be stranded
		has(t, run(t, admin, adPW, "ppolicy", "list"), "e2e.pol")

		// once nobody points at it, it goes
		run(t, admin, adPW, "ppolicy", "assign", "e2e.beta", "--clear")
		run(t, root, rtPW, "ppolicy", "delete", "e2e.pol")

		// and the seeded directory has no stranded reference
		has(t, run(t, admin, adPW, "ppolicy", "check"), "all resolve")
	})

	t.Run("config", func(t *testing.T) {
		has(t, run(t, admin, adPW, "config", "db", "list"), "olcDatabase")
		// resize: only exercise arg parsing/wiring — a live olcDbMaxSize remap can
		// intermittently disrupt/restart slapd (racy with active txns), which would
		// flake later subtests. The bad-unit path mutates nothing.
		if _, se, rerr := try(root, rtPW, "config", "db", "resize", "olcDatabase={1}mdb,cn=config", "4Zorks"); rerr == nil || !strings.Contains(se, "unknown size unit") {
			t.Errorf("config db resize bad unit: err=%v stderr=%s", rerr, se)
		}
		has(t, run(t, admin, adPW, "config", "overlay", "list"), "memberof     active")
		// overlay lifecycle on `constraint`: nothing in the seed depends on it, so
		// enabling it is inert. First run also exercises the module-load path
		// (constraint.so is not in the bootstrap's olcModuleLoad list).
		has(t, run(t, admin, adPW, "config", "overlay", "enable", "constraint"), "overlay constraint created")
		has(t, run(t, admin, adPW, "config", "overlay", "enable", "constraint"), "overlay constraint unchanged")
		has(t, run(t, admin, adPW, "config", "overlay", "disable", "constraint"), "overlay constraint disabled")
		has(t, run(t, admin, adPW, "config", "overlay", "list"), "DISABLED")
		has(t, run(t, admin, adPW, "config", "overlay", "enable", "constraint"), "overlay constraint re-enabled")
		has(t, run(t, admin, adPW, "config", "overlay", "disable", "constraint", "--purge"), "overlay constraint deleted")
		// a missing module must be named, not surfaced as slapd's opaque
		// "objectClass: value #1 invalid per syntax"
		if _, se, oerr := try(admin, adPW, "config", "overlay", "enable", "valsort", "--no-module"); oerr == nil || !strings.Contains(se, "is not loaded") {
			t.Errorf("config overlay enable --no-module: err=%v stderr=%s", oerr, se)
		}
		has(t, run(t, admin, adPW, "config", "acl", "list", "olcDatabase={1}mdb,cn=config"), "olcAccess")
		// reorder an olcAccess rule and put it back (live, no restart). These two
		// rules have disjoint targets, so the move changes nothing but the order.
		db := "olcDatabase={1}mdb,cn=config"
		has(t, run(t, root, rtPW, "config", "acl", "move", db, "0", "1"), "moved olcAccess {0} to {1}")
		run(t, root, rtPW, "config", "acl", "move", db, "1", "0")

		// A move that would silently change access is refused, not applied. The
		// seed's ou=users rule ends in `by * none`; a narrow rule raised above it
		// takes that rule's grantees off the subtree — which `lint` cannot see,
		// because nothing becomes unreachable.
		//
		// olcAccess is snapshotted and restored verbatim: `acl revoke --dn` would
		// strip that identity from every seed rule, and a rule ending in `by * none`
		// survives a revoke by design (an explicit deny is not leftover noise).
		snapshot := aclValues(t, db)
		defer restoreACL(t, db, snapshot)

		narrow := `to dn.subtree="ou=e2e.mv,ou=users,dc=example,dc=org" by dn.exact="cn=admin,ou=users,dc=example,dc=org" read by * none`
		run(t, root, rtPW, "entry", "set", "--config-bind", db, "olcAccess", narrow, "--add")
		last := strconv.Itoa(len(snapshot)) // appended after the seed's rules
		_, se, merr := try(root, rtPW, "config", "acl", "move", db, last, "4")
		if merr == nil {
			t.Error("config acl move: a move that revokes access was applied instead of refused")
		}
		for _, want := range []string{"would silently change access", "cn=phpldapadmin", "--force"} {
			if !strings.Contains(se, want) {
				t.Errorf("move refusal missing %q in:\n%s", want, se)
			}
		}
		// a refusal must not have written anything
		has(t, run(t, admin, adPW, "config", "acl", "list", db), "{"+last+"}to dn.subtree=\"ou=e2e.mv")
		// --force does it anyway
		has(t, run(t, root, rtPW, "config", "acl", "move", db, last, "4", "--force"), "moved olcAccess {"+last+"} to {4}")
		run(t, root, rtPW, "config", "acl", "move", db, "4", last, "--force")

		// `acl delete` removes one rule by its exact stored value. A DEAD rule
		// (what lint reports) is the safe case: it grants nothing, so removing it
		// changes nothing and needs no --force. It is also the only way out —
		// `acl revoke` keeps a deliberate `by * none`.
		has(t, run(t, admin, adPW, "config", "acl", "lint", db), "[dead] {"+last+"}")
		has(t, run(t, root, rtPW, "config", "acl", "delete", db, last), "deleted olcAccess {"+last+"}")
		has(t, run(t, admin, adPW, "config", "acl", "lint", db), "no dead or empty rules")
		// deleting a LIVE rule hands its entries to whatever is below: refused
		_, se, derr := try(root, rtPW, "config", "acl", "delete", db, "4")
		if derr == nil {
			t.Error("config acl delete: a live rule was deleted instead of refused")
		}
		for _, want := range []string{"would silently change access", "stop applying", "--force"} {
			if !strings.Contains(se, want) {
				t.Errorf("delete refusal missing %q in:\n%s", want, se)
			}
		}
		if _, _, derr = try(root, rtPW, "config", "acl", "delete", db, "99"); derr == nil {
			t.Error("config acl delete: a bad index was accepted")
		}
		// grant a group read on a subtree (by group.exact clause), then revoke
		has(t, run(t, admin, adPW, "config", "acl", "grant", db, "ou=users,dc=example,dc=org", "--group", "e2e.devs", "--access", "read"),
			`granted read to group.exact="cn=e2e.devs`)
		has(t, run(t, admin, adPW, "config", "acl", "list", db), `by group.exact="cn=e2e.devs`)
		// this target already has a rule in the seed, so the grant only added a
		// `by` clause to it: revoking leaves the rule's other clauses standing
		has(t, run(t, admin, adPW, "config", "acl", "revoke", db, "--group", "e2e.devs"), "revoked 1 clause")
		// the "app must search a tree and read only some entries" pattern:
		// base-scope container grant + filtered read grant. Neither passes --at:
		// a NEW rule must land above the broad ou=users rule that would shadow it,
		// or the grant would be dead on arrival (lint asserts this below).
		has(t, run(t, admin, adPW, "config", "acl", "grant", db, "ou=users,dc=example,dc=org",
			"--group", "e2e.devs", "--access", "search", "--scope", "base"), `to dn.base="ou=users`)
		has(t, run(t, admin, adPW, "config", "acl", "grant", db, "ou=users,dc=example,dc=org",
			"--group", "e2e.devs", "--access", "read",
			"--filter", "(memberOf=cn=e2e.devs,ou=groups,dc=example,dc=org)"), "filter=(memberOf=cn=e2e.devs")
		has(t, run(t, admin, adPW, "config", "acl", "lint", db), "no dead or empty rules")
		// both --at grants created a rule whose ONLY grantee is e2e.devs, so this
		// revoke must take both rules with it rather than leave `by * break`
		// shells behind (this suite used to accumulate two of them per run).
		has(t, run(t, admin, adPW, "config", "acl", "revoke", db, "--group", "e2e.devs"), "2 now-empty rule(s) dropped")
		// revoke leaves the database exactly as it found it
		has(t, run(t, admin, adPW, "config", "acl", "lint", db), "no dead or empty rules")
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

// aclValues returns the database's olcAccess rule bodies, in index order and
// without the {N} prefixes — the form `entry set` takes to write them back.
func aclValues(t *testing.T, db string) []string {
	t.Helper()
	var res struct {
		Attrs map[string][]string `json:"attrs"`
	}
	out := run(t, admin, adPW, "-o", "json", "config", "acl", "list", db)
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("parse acl list: %v\n%s", err, out)
	}
	values := res.Attrs["olcAccess"]
	if len(values) == 0 {
		t.Fatal("acl list returned no olcAccess")
	}
	bodies := make([]string, len(values))
	for i, v := range values {
		bodies[i] = v[strings.IndexByte(v, '}')+1:] // values come back ordered
	}
	return bodies
}

// restoreACL puts olcAccess back exactly as aclValues found it.
func restoreACL(t *testing.T, db string, bodies []string) {
	t.Helper()
	args := append([]string{"entry", "set", "--config-bind", db, "olcAccess"}, bodies...)
	run(t, root, rtPW, args...)
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

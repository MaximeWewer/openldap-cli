package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `# top comment — keep me
default: dev
profiles:
  dev:
    url: ldap://dev
    base_dn: dc=dev
  prod:
    url: ldap://prod
    base_dn: dc=prod
    bind_dn: cn=admin,dc=prod
`

func writeSample(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaultProfile(t *testing.T) {
	p := writeSample(t)
	prof, err := Load(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if prof.URL != "ldap://dev" || prof.BaseDN != "dc=dev" {
		t.Errorf("got %+v, want dev profile", prof)
	}
}

func TestLoadNamedProfile(t *testing.T) {
	p := writeSample(t)
	prof, err := Load(p, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if prof.URL != "ldap://prod" || prof.BindDN != "cn=admin,dc=prod" {
		t.Errorf("got %+v, want prod profile", prof)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	p := writeSample(t)
	t.Setenv("LDAP_URL", "ldap://env")
	t.Setenv("LDAP_BASE_DN", "dc=env")
	prof, err := Load(p, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if prof.URL != "ldap://env" || prof.BaseDN != "dc=env" {
		t.Errorf("env override failed: %+v", prof)
	}
}

func TestLoadSASLExternalEnv(t *testing.T) {
	p := writeSample(t)
	t.Setenv("LDAP_SASL_EXTERNAL", "true")
	prof, err := Load(p, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if !prof.SASLExternal {
		t.Errorf("LDAP_SASL_EXTERNAL=true did not set SASLExternal: %+v", prof)
	}
}

func TestLoadMissingURL(t *testing.T) {
	p := writeSample(t)
	if _, err := Load(p, "ghost"); err == nil {
		t.Error("expected error for profile with no url")
	}
}

func TestProfileNames(t *testing.T) {
	p := writeSample(t)
	names, def, err := ProfileNames(p)
	if err != nil {
		t.Fatal(err)
	}
	if def != "dev" {
		t.Errorf("default = %q", def)
	}
	if strings.Join(names, ",") != "dev,prod" {
		t.Errorf("names = %v", names)
	}
}

func TestSetDefaultPreservesComments(t *testing.T) {
	p := writeSample(t)
	if err := SetDefault(p, "prod"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	s := string(raw)
	if !strings.Contains(s, "default: prod") {
		t.Errorf("default not switched:\n%s", s)
	}
	if !strings.Contains(s, "# top comment — keep me") {
		t.Error("comment was lost")
	}
	if strings.Contains(s, "default: dev") {
		t.Error("old default still present")
	}
}

func TestSetDefaultUnknown(t *testing.T) {
	p := writeSample(t)
	if err := SetDefault(p, "nope"); err == nil {
		t.Error("expected error for unknown profile")
	}
}

func TestEnvBoolRejectsNonBoolean(t *testing.T) {
	// a typo in LDAP_START_TLS used to be swallowed, leaving the bind in
	// cleartext while the operator believed TLS was on
	t.Setenv("LDAP_URL", "ldap://localhost:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("LDAP_START_TLS", "yes")

	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml"), ""); err == nil {
		t.Fatal("Load accepted LDAP_START_TLS=yes; want an error")
	}
}

func TestEnvBoolAcceptsBoolean(t *testing.T) {
	t.Setenv("LDAP_URL", "ldap://localhost:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("LDAP_START_TLS", "true")

	p, err := Load(filepath.Join(t.TempDir(), "absent.yaml"), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !p.StartTLS {
		t.Error("StartTLS = false, want true")
	}
}

func TestEnvFileReadsTheSecret(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "bindpw")
	// the trailing newline `echo` leaves must not become part of the password
	if err := os.WriteFile(pwFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LDAP_URL", "ldap://localhost:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("LDAP_BIND_PW_FILE", pwFile)

	p, err := Load(filepath.Join(dir, "absent.yaml"), "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.BindPW != "s3cret" {
		t.Errorf("BindPW = %q, want %q", p.BindPW, "s3cret")
	}
}

func TestEnvFileReportsAMissingFile(t *testing.T) {
	t.Setenv("LDAP_URL", "ldap://localhost:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("LDAP_BIND_PW_FILE", filepath.Join(t.TempDir(), "nope"))

	if _, err := Load("", ""); err == nil {
		t.Fatal("Load ignored an unreadable LDAP_BIND_PW_FILE")
	}
}

func TestWarnsOnAWorldReadableConfigHoldingASecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf.yaml")
	body := "default: dev\nprofiles:\n  dev:\n    url: ldap://localhost:389\n" +
		"    base_dn: dc=example,dc=org\n    bind_pw: hunter2\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "dev"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(Insecurities) == 0 {
		t.Error("no warning for a 0644 config file holding bind_pw")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "dev"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(Insecurities) != 0 {
		t.Errorf("warned about a 0600 config file: %s", Insecurities)
	}
}

// warnedAbout reports whether any warning mentions sub.
func warnedAbout(sub string) bool {
	for _, w := range Insecurities {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestWarnsOnACleartextBindOverTheNetwork(t *testing.T) {
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=org")
	t.Setenv("LDAP_BIND_PW", "secret")
	absent := filepath.Join(t.TempDir(), "absent.yaml")

	cases := map[string]bool{
		"ldap://ldap.example.org:389":  true,  // the whole point
		"ldaps://ldap.example.org:636": false, // encrypted
		"ldap://localhost:389":         false, // no network to listen on
		"ldap://127.0.0.1:389":         false,
		"ldap://[::1]:389":             false,
	}
	for url, want := range cases {
		t.Setenv("LDAP_URL", url)
		if _, err := Load(absent, ""); err != nil {
			t.Fatalf("Load(%s): %v", url, err)
		}
		if got := warnedAbout("in the clear"); got != want {
			t.Errorf("%s: cleartext warning = %v, want %v (%v)", url, got, want, Insecurities)
		}
	}
}

func TestNoCleartextWarningWithoutASecretOrWithTLSUpgrade(t *testing.T) {
	t.Setenv("LDAP_URL", "ldap://ldap.example.org:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	absent := filepath.Join(t.TempDir(), "absent.yaml")

	// an anonymous bind sends no password, so nothing is at risk
	if _, err := Load(absent, ""); err != nil {
		t.Fatal(err)
	}
	if warnedAbout("in the clear") {
		t.Errorf("warned about an anonymous bind: %v", Insecurities)
	}

	// and StartTLS encrypts before the bind happens
	t.Setenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=org")
	t.Setenv("LDAP_BIND_PW", "secret")
	t.Setenv("LDAP_START_TLS", "true")
	if _, err := Load(absent, ""); err != nil {
		t.Fatal(err)
	}
	if warnedAbout("in the clear") {
		t.Errorf("warned despite start_tls: %v", Insecurities)
	}
}

func TestWarnsOnAWorldReadableClientKey(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "client.key")
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LDAP_URL", "ldaps://ldap.example.org:636")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("LDAP_CLIENT_KEY", key)

	if _, err := Load(filepath.Join(dir, "absent.yaml"), ""); err != nil {
		t.Fatal(err)
	}
	if !warnedAbout("private key") {
		t.Errorf("no warning for a 0644 client key: %v", Insecurities)
	}

	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "absent.yaml"), ""); err != nil {
		t.Fatal(err)
	}
	if warnedAbout("private key") {
		t.Errorf("warned about a 0600 client key: %v", Insecurities)
	}
}

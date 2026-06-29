package domain

import "testing"

func TestParseUserDerivation(t *testing.T) {
	u, err := ParseUser("Toto.Titi", "example.org")
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"UID": u.UID, "CN": u.CN, "SN": u.SN, "GivenName": u.GivenName,
		"DisplayName": u.DisplayName, "Mail": u.Mail,
	}
	want := map[string]string{
		"UID": "toto.titi", "CN": "toto.titi", "SN": "Titi", "GivenName": "Toto",
		"DisplayName": "Toto Titi", "Mail": "toto.titi@example.org",
	}
	for k, v := range want {
		if checks[k] != v {
			t.Errorf("%s = %q, want %q", k, checks[k], v)
		}
	}
}

func TestParseUserInvalid(t *testing.T) {
	// empty, or a dot with an empty side
	for _, in := range []string{"", "  ", ".", "a.", ".b"} {
		if _, err := ParseUser(in, "x"); err == nil {
			t.Errorf("ParseUser(%q) expected error", in)
		}
	}
}

func TestParseUserPlain(t *testing.T) {
	u, err := ParseUser("Demo1", "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if u.UID != "demo1" || u.CN != "demo1" || u.SN != "demo1" {
		t.Errorf("got %+v, want uid/cn/sn=demo1", u)
	}
	if u.GivenName != "" {
		t.Errorf("GivenName = %q, want empty for plain login", u.GivenName)
	}
	if u.Mail != "demo1@example.org" {
		t.Errorf("Mail = %q", u.Mail)
	}
	// a plain login must not emit an empty givenName attribute
	for _, a := range u.Attributes(nil) {
		if a.Name == "givenName" {
			t.Error("plain login should not produce a givenName attribute")
		}
	}
}

func TestParseUserNoMailDomain(t *testing.T) {
	u, _ := ParseUser("a.b", "")
	if u.Mail != "" {
		t.Errorf("Mail = %q, want empty when no mail domain", u.Mail)
	}
}

func TestDN(t *testing.T) {
	u, _ := ParseUser("a.b", "")
	if got := u.DN("ou=users", "dc=x"); got != "cn=a.b,ou=users,dc=x" {
		t.Errorf("DN = %q", got)
	}
	if got := u.DN("", "dc=x"); got != "cn=a.b,dc=x" {
		t.Errorf("DN (no ou) = %q", got)
	}
}

func TestAttributesPosix(t *testing.T) {
	u, _ := ParseUser("a.b", "example.org")
	attrs := u.Attributes(&Posix{UIDNumber: 1000, GIDNumber: 1000})
	found := map[string][]string{}
	for _, a := range attrs {
		found[a.Name] = a.Values
	}
	if oc := found["objectClass"]; len(oc) == 0 || oc[len(oc)-1] != "posixAccount" {
		t.Errorf("objectClass = %v, want posixAccount", found["objectClass"])
	}
	if found["uidNumber"][0] != "1000" {
		t.Errorf("uidNumber = %v", found["uidNumber"])
	}
	if found["homeDirectory"][0] != "/home/a.b" {
		t.Errorf("homeDirectory = %v", found["homeDirectory"])
	}
}

func TestAttributeMap(t *testing.T) {
	u, _ := ParseUser("a.b", "example.org")
	m := u.AttributeMap("secret", nil)
	if got := m["userPassword"]; len(got) != 1 || got[0] != "secret" {
		t.Errorf("userPassword = %v", got)
	}
	if got := m["cn"]; len(got) != 1 || got[0] != "a.b" {
		t.Errorf("cn = %v", got)
	}
	if _, ok := m["objectClass"]; !ok {
		t.Error("objectClass missing")
	}
}

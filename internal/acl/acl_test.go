package acl

import "testing"

func TestSplitIndexed(t *testing.T) {
	cases := []struct {
		in   string
		idx  int
		body string
	}{
		{"{2}to x", 2, "to x"},
		{"{12}foo", 12, "foo"},
		{"to x", -1, "to x"},
		{"{bad}x", -1, "{bad}x"},
	}
	for _, c := range cases {
		idx, body := SplitIndexed(c.in)
		if idx != c.idx || body != c.body {
			t.Errorf("SplitIndexed(%q) = (%d,%q), want (%d,%q)", c.in, idx, body, c.idx, c.body)
		}
	}
}

func TestInjectInsertsBeforeNone(t *testing.T) {
	svc := `cn=svc,ou=service-accounts,dc=example,dc=org`
	values := []string{
		`{0}to attrs=userPassword by self write by * none`,
		`{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`,
	}
	edit, appended := Inject(values, "ou=users,dc=example,dc=org", svc, "read")
	if appended {
		t.Fatal("expected insert, got append")
	}
	if edit.Delete != values[1] {
		t.Errorf("Delete = %q, want %q", edit.Delete, values[1])
	}
	want := `{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by dn.exact="` + svc + `" read by * none`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}
}

func TestInjectAppendsWhenMissing(t *testing.T) {
	svc := `cn=svc,ou=service-accounts,dc=example,dc=org`
	values := []string{`{0}to attrs=userPassword by * none`}
	edit, appended := Inject(values, "ou=contractors,dc=example,dc=org", svc, "write")
	if !appended {
		t.Fatal("expected append")
	}
	if edit.Delete != "" {
		t.Errorf("Delete = %q, want empty", edit.Delete)
	}
	want := `to dn.subtree="ou=contractors,dc=example,dc=org" by dn.exact="` + svc + `" write by * none`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}
}

func TestRemoveGrantee(t *testing.T) {
	svc := `cn=svc,ou=service-accounts,dc=example,dc=org`
	values := []string{
		`{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by dn.exact="` + svc + `" read by * none`,
		`{5}to dn.base="dc=example,dc=org" by * read`,
	}
	edits, removed := RemoveGrantee(values, svc)
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if len(edits) != 1 || edits[0].Delete != values[0] {
		t.Fatalf("unexpected edits: %+v", edits)
	}
	want := `{4}to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`
	if edits[0].Add != want {
		t.Errorf("Add = %q, want %q", edits[0].Add, want)
	}
}

func TestRemoveGranteeNoMatch(t *testing.T) {
	values := []string{`{0}to * by * read`}
	edits, removed := RemoveGrantee(values, "cn=absent,dc=x")
	if removed != 0 || edits != nil {
		t.Errorf("expected no edits, got %d / %+v", removed, edits)
	}
}

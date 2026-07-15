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
	edit, appended := Inject(values, "ou=users,dc=example,dc=org", DNWho(svc), "read")
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
	edit, appended := Inject(values, "ou=contractors,dc=example,dc=org", DNWho(svc), "write")
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
	edits, removed := RemoveGrantee(values, DNWho(svc))
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
	edits, removed := RemoveGrantee(values, DNWho("cn=absent,dc=x"))
	if removed != 0 || edits != nil {
		t.Errorf("expected no edits, got %d / %+v", removed, edits)
	}
}

func TestReorder(t *testing.T) {
	// intentionally out of order to prove it sorts by index first
	vals := []string{"{5}to dn.subtree=g by X write by * none", "{8}to dn.subtree=g/vcf by Y read by * none", "{0}to * by * break"}

	// move {8} above {5} -> position 1
	got, err := Reorder(vals, 2, 1)
	if err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	want := []string{"to * by * break", "to dn.subtree=g/vcf by Y read by * none", "to dn.subtree=g by X write by * none"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pos %d = %q, want %q", i, got[i], want[i])
		}
	}

	// no-op move returns the sorted, unindexed bodies
	same, _ := Reorder(vals, 0, 0)
	if same[0] != "to * by * break" {
		t.Errorf("no-op first = %q", same[0])
	}

	// out of range
	if _, err := Reorder(vals, 0, 9); err == nil {
		t.Error("expected out-of-range error")
	}
	if _, err := Reorder(nil, 0, 0); err == nil {
		t.Error("expected empty error")
	}
}

func TestInjectGroupWho(t *testing.T) {
	g := `cn=readers,ou=groups,dc=example,dc=org`
	values := []string{`{4}to dn.subtree="ou=x,dc=example,dc=org" by dn.exact="cn=sa1,dc=example,dc=org" read by * none`}
	edit, appended := Inject(values, "ou=x,dc=example,dc=org", GroupWho(g), "read")
	if appended {
		t.Fatal("expected insert into existing rule")
	}
	want := `{4}to dn.subtree="ou=x,dc=example,dc=org" by dn.exact="cn=sa1,dc=example,dc=org" read by group.exact="` + g + `" read by * none`
	if edit.Add != want {
		t.Errorf("Add = %q, want %q", edit.Add, want)
	}
}

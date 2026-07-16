package acl

import "testing"

// the real prod case: a specific grant at {8} shadowed by the broad ou=groups
// rule at {5} — the SA "had" read on cn=vcf-admin but the rule never fired.
func TestLintDetectsRealShadowedRule(t *testing.T) {
	values := []string{
		`{0}to * by dn.exact="cn=replicator,dc=x" read by * break`,
		`{5}to dn.subtree="ou=groups,dc=x" by dn.exact="cn=admin,dc=x" write by * none`,
		`{8}to dn.subtree="cn=vcf-admin,ou=groups,dc=x" by dn.exact="cn=vcf,dc=x" read by * none`,
	}
	f := Lint(values)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].Index != 8 || f[0].Level != LevelDead {
		t.Errorf("finding = %+v, want dead on {8}", f[0])
	}
	// {0} is `to *` but ends in `by * break`, so it must NOT be blamed
	if got := f[0].Message; !contains(got, "{5}") || contains(got, "{0}") {
		t.Errorf("message should blame {5}, not {0}: %q", got)
	}
}

func TestLintCleanWhenOrderedOrBreaking(t *testing.T) {
	// specific rule placed ABOVE the broad one -> reachable
	ok := []string{
		`{5}to dn.subtree="cn=vcf-admin,ou=groups,dc=x" by dn.exact="cn=vcf,dc=x" read by * break`,
		`{6}to dn.subtree="ou=groups,dc=x" by dn.exact="cn=admin,dc=x" write by * none`,
	}
	if f := Lint(ok); len(f) != 0 {
		t.Errorf("expected no findings, got %+v", f)
	}
	// broad rule breaks -> the later specific rule is still reachable
	brk := []string{
		`{5}to dn.subtree="ou=groups,dc=x" by dn.exact="cn=admin,dc=x" write by * break`,
		`{8}to dn.subtree="cn=vcf-admin,ou=groups,dc=x" by dn.exact="cn=vcf,dc=x" read by * none`,
	}
	if f := Lint(brk); len(f) != 0 {
		t.Errorf("break should keep {8} reachable, got %+v", f)
	}
}

func TestLintFilteredRuleDoesNotShadow(t *testing.T) {
	// a filtered rule only matches a subset -> never treated as covering
	v := []string{
		`{4}to dn.subtree="ou=users,dc=x" filter=(memberOf=cn=g,dc=x) by dn.exact="cn=app,dc=x" read by * break`,
		`{5}to dn.subtree="ou=users,dc=x" by self write by * none`,
	}
	if f := Lint(v); len(f) != 0 {
		t.Errorf("filtered rule must not shadow, got %+v", f)
	}
	// but an unfiltered broad rule DOES shadow a later filtered one
	v2 := []string{
		`{4}to dn.subtree="ou=users,dc=x" by self write by * none`,
		`{5}to dn.subtree="ou=users,dc=x" filter=(memberOf=cn=g,dc=x) by dn.exact="cn=app,dc=x" read by * break`,
	}
	f := Lint(v2)
	if len(f) != 1 || f[0].Index != 5 || f[0].Level != LevelDead {
		t.Errorf("want dead on {5}, got %+v", f)
	}
}

func TestLintOrphanRule(t *testing.T) {
	v := []string{`{3}to dn.subtree="ou=x,dc=x" by * break`}
	f := Lint(v)
	if len(f) != 1 || f[0].Level != LevelWarn {
		t.Fatalf("want a warn for the do-nothing rule, got %+v", f)
	}
}

// a catch-all with a real action is a deliberate public grant/deny, not a leftover
func TestLintCatchAllWithActionIsNotFlagged(t *testing.T) {
	for _, v := range [][]string{
		{`{1}to dn.subtree="ou=policies,dc=x" by * read`},
		{`{2}to dn.subtree="ou=svc,dc=x" by * none`},
	} {
		if f := Lint(v); len(f) != 0 {
			t.Errorf("%v must not be flagged, got %+v", v, f)
		}
	}
}

func TestLintBaseScopeDoesNotShadowSubtree(t *testing.T) {
	// a dn.base rule covers only the container entry, not the tree below it
	v := []string{
		`{4}to dn.base="ou=users,dc=x" by dn.exact="cn=app,dc=x" search by * none`,
		`{5}to dn.subtree="ou=users,dc=x" by self write by * none`,
	}
	if f := Lint(v); len(f) != 0 {
		t.Errorf("dn.base must not shadow the subtree rule, got %+v", f)
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

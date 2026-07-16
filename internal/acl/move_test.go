package acl

import (
	"slices"
	"strings"
	"testing"
)

// The trap the guard exists for, reproduced from the live seed: a narrow rule
// ending in `by * none` raised above the broad ou=users rule takes that rule's
// other grantees off the narrow subtree. Lint sees nothing (no rule became
// unreachable) — this is the check that does.
func TestInspectMoveDetectsGranteesLosingAccess(t *testing.T) {
	broad := `to dn.subtree="ou=users,dc=example,dc=org" by self write by dn.exact="cn=admin,ou=users,dc=example,dc=org" write by dn.exact="cn=phpldapadmin,ou=service-accounts,dc=example,dc=org" read by * none`
	narrow := `to dn.subtree="ou=sub,ou=users,dc=example,dc=org" by dn.exact="cn=admin,ou=users,dc=example,dc=org" read by * none`
	values := []string{`{0}` + broad, `{1}` + narrow}

	bodies, impact, err := InspectMove(values, 1, 0)
	if err != nil {
		t.Fatalf("InspectMove: %v", err)
	}
	if !slices.Equal(bodies, []string{narrow, broad}) {
		t.Fatalf("bodies = %q", bodies)
	}
	if impact.Empty() {
		t.Fatal("impact is empty: the move silently revokes access and must be reported")
	}
	// Reported per CLAUSE, not per grantee: self and phpldapadmin lose their
	// access outright, and admin's `write` stops applying too — the narrow rule
	// only grants it `read`, so the move downgrades it. A downgrade is a loss
	// worth naming. `by * none` is not: losing it is the point of the move.
	want := []string{
		`by self write`,
		`by dn.exact="cn=admin,ou=users,dc=example,dc=org" write`,
		`by dn.exact="cn=phpldapadmin,ou=service-accounts,dc=example,dc=org" read`,
	}
	if !slices.Equal(impact.Lost, want) {
		t.Errorf("Lost = %q, want %q", impact.Lost, want)
	}
	if len(impact.Dead) != 0 {
		t.Errorf("Dead = %v, want none (nothing became unreachable)", impact.Dead)
	}
}

// The same move with `by * break` is purely additive: evaluation continues to
// the broader rule, so nobody loses anything.
func TestInspectMoveBreakingRuleLosesNothing(t *testing.T) {
	broad := `to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`
	narrow := `to dn.subtree="ou=sub,ou=users,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * break`
	values := []string{`{0}` + broad, `{1}` + narrow}

	_, impact, err := InspectMove(values, 1, 0)
	if err != nil {
		t.Fatalf("InspectMove: %v", err)
	}
	if !impact.Empty() {
		t.Errorf("impact = %+v, want empty: a `by * break` rule is additive", impact)
	}
}

// Moving a rule DOWN under a broader non-breaking one makes it unreachable —
// the case Lint does catch, reported here before the write rather than after.
func TestInspectMoveDetectsNewlyDeadRule(t *testing.T) {
	narrow := `to dn.subtree="ou=sub,ou=users,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * break`
	broad := `to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`
	values := []string{`{0}` + narrow, `{1}` + broad}

	_, impact, err := InspectMove(values, 0, 1)
	if err != nil {
		t.Fatalf("InspectMove: %v", err)
	}
	if len(impact.Dead) != 1 {
		t.Fatalf("Dead = %v, want the narrow rule", impact.Dead)
	}
	if !strings.Contains(impact.Dead[0].Rule, "ou=sub") {
		t.Errorf("Dead rule = %q", impact.Dead[0].Rule)
	}
}

// A rule that was ALREADY dead before the move is not the move's doing: only
// newly-dead rules are reported, or every move on a messy tree would be blocked.
func TestInspectMoveIgnoresPreExistingDeadRules(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by self write by * none`,
		`{1}to dn.subtree="ou=sub,ou=users,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * break`, // already dead
		`{2}to dn.subtree="ou=groups,dc=example,dc=org" by * read`,
		`{3}to dn.base="dc=example,dc=org" by * read`,
	}
	// move two unrelated rules; the dead one stays dead but is not our fault
	_, impact, err := InspectMove(values, 2, 3)
	if err != nil {
		t.Fatalf("InspectMove: %v", err)
	}
	if len(impact.Dead) != 0 {
		t.Errorf("Dead = %v, want none (it was already dead before the move)", impact.Dead)
	}
}

// Reordering rules with disjoint targets changes nothing but the order.
func TestInspectMoveDisjointRulesAreSafe(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by * read`,
		`{1}to dn.subtree="ou=groups,dc=example,dc=org" by * read`,
		`{2}to dn.subtree="ou=policies,dc=example,dc=org" by * read`,
	}
	_, impact, err := InspectMove(values, 2, 0)
	if err != nil {
		t.Fatalf("InspectMove: %v", err)
	}
	if !impact.Empty() {
		t.Errorf("impact = %+v, want empty", impact)
	}
}

func TestInspectMoveRejectsBadIndex(t *testing.T) {
	values := []string{`{0}to * by * read`}
	if _, _, err := InspectMove(values, 0, 5); err == nil {
		t.Error("expected an out-of-range error")
	}
}

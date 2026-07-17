package acl

import (
	"slices"
	"strings"
	"testing"
)

func TestFindRule(t *testing.T) {
	values := []string{
		`{2}to dn.base="c" by * read`,
		`{0}to * by * none`,
		`{1}to dn.base="b" by * read`,
	}
	// indexes are matched on the {N} the server stored, not on list position
	if got, err := FindRule(values, 2); err != nil || got != `{2}to dn.base="c" by * read` {
		t.Errorf("FindRule(2) = %q, %v", got, err)
	}
	if _, err := FindRule(values, 7); err == nil || !strings.Contains(err.Error(), "{0}..{2}") {
		t.Errorf("FindRule(7) error = %v, want the available range", err)
	}
	if _, err := FindRule(nil, 0); err == nil {
		t.Error("FindRule on an empty list: want an error")
	}
}

// The case this command exists for: a rule an earlier one shadows never fires,
// so removing it changes nothing. It must not need --force.
func TestInspectDeleteDeadRuleChangesNothing(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=groups,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * none`,
		// shadowed by {0}: same entries, and {0} never breaks
		`{1}to dn.subtree="cn=team,ou=groups,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * none`,
	}
	value, impact, err := InspectDelete(values, 1)
	if err != nil {
		t.Fatalf("InspectDelete: %v", err)
	}
	if value != values[1] {
		t.Errorf("value = %q, want the exact stored string", value)
	}
	if !impact.Empty() {
		t.Errorf("impact = %+v, want empty: a dead rule grants nothing, so removing it changes nothing", impact)
	}
}

// Deleting a LIVE rule hands its entries to whatever sits below — that is a
// silent access change and must be reported.
func TestInspectDeleteLiveRuleReportsWhatIsLost(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by self write by dn.exact="cn=app,dc=example,dc=org" read by * none`,
		`{1}to * by dn.exact="cn=admin,dc=example,dc=org" write by * none`,
	}
	_, impact, err := InspectDelete(values, 0)
	if err != nil {
		t.Fatalf("InspectDelete: %v", err)
	}
	if impact.Empty() {
		t.Fatal("impact is empty: deleting a live rule silently changes access")
	}
	// `to *` below now answers for ou=users; self and app lose what {0} gave
	want := []string{`by self write`, `by dn.exact="cn=app,dc=example,dc=org" read`}
	if !slices.Equal(impact.Lost, want) {
		t.Errorf("Lost = %q, want %q", impact.Lost, want)
	}
	// Decided is the rule that answered BEFORE — for a delete that is the rule
	// itself; Now is the one that takes over. Confusing the two makes the
	// refusal claim the deleted rule replaces itself. Both are rule BODIES,
	// without the {N} the stored value carries.
	if _, body := SplitIndexed(values[0]); impact.Decided != body {
		t.Errorf("Decided = %q, want the deleted rule", impact.Decided)
	}
	if _, body := SplitIndexed(values[1]); impact.Now != body {
		t.Errorf("Now = %q, want the rule that takes over", impact.Now)
	}
}

// When nothing below covers the entries, there is no new decider: Now must be
// empty so the caller can say "access falls back to denied" instead of naming a
// rule that does not exist.
func TestInspectDeleteNoRuleTakesOver(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=app,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * none`,
		`{1}to dn.subtree="ou=other,dc=example,dc=org" by * read`,
	}
	_, impact, err := InspectDelete(values, 0)
	if err != nil {
		t.Fatalf("InspectDelete: %v", err)
	}
	if impact.Now != "" {
		t.Errorf("Now = %q, want empty: no rule below covers ou=app", impact.Now)
	}
}

// Deleting a broad rule can REVIVE one it was shadowing — an access change in
// the other direction. It must not be reported as newly dead.
func TestInspectDeleteDoesNotReportRevivedRuleAsDead(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=users,dc=example,dc=org" by * none`,
		`{1}to dn.subtree="ou=users,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * break`,
	}
	_, impact, err := InspectDelete(values, 0)
	if err != nil {
		t.Fatalf("InspectDelete: %v", err)
	}
	for _, f := range impact.Dead {
		if strings.Contains(f.Rule, "cn=app") {
			t.Errorf("the revived rule was reported as newly dead: %q", f.Rule)
		}
	}
}

// A rule with no rule below covering its entries: nothing takes over, so there
// is no "new decider" to diff against — but the access is still gone.
func TestInspectDeleteSoleRuleForItsTree(t *testing.T) {
	values := []string{
		`{0}to dn.subtree="ou=app,dc=example,dc=org" by dn.exact="cn=app,dc=example,dc=org" read by * none`,
		`{1}to dn.base="dc=example,dc=org" by * read`,
	}
	value, _, err := InspectDelete(values, 0)
	if err != nil {
		t.Fatalf("InspectDelete: %v", err)
	}
	if value != values[0] {
		t.Errorf("value = %q", value)
	}
}

func TestInspectDeleteBadIndex(t *testing.T) {
	if _, _, err := InspectDelete([]string{`{0}to * by * read`}, 9); err == nil {
		t.Error("want an out-of-range error")
	}
}

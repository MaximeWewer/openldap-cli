package acl

import (
	"fmt"
	"strings"
)

// Reordering olcAccess is not just cosmetic: slapd stops at the first rule whose
// `to` matches, so moving a rule changes WHICH rule decides for the entries it
// covers. Raising a rule that ends in `by * none` above a broader one takes the
// broader rule's grantees off those entries — silently, and `Lint` cannot see it
// (nothing became unreachable; the broader rule still decides everywhere else).
// InspectMove is that missing check.

// MoveImpact is what a reorder would silently change.
type MoveImpact struct {
	Moved string // the rule being moved
	// Lost are the `by` clauses that stop applying to Moved's entries, because
	// the rule that used to decide for them no longer gets the chance.
	Lost []string
	// Decided is the rule that used to decide for Moved's entries.
	Decided string
	// Dead are the rules the move newly makes unreachable.
	Dead []Finding
}

// Empty reports whether the move changes nothing beyond the order itself.
func (m MoveImpact) Empty() bool { return len(m.Lost) == 0 && len(m.Dead) == 0 }

// ruleSelector returns the parsed `to …` part of a rule body.
func ruleSelector(body string) selector {
	s := body
	if i := strings.Index(body, " by "); i >= 0 {
		s = body[:i]
	}
	return parseSelector(s)
}

// firstDecider returns the body of the earliest rule that matches everything sel
// matches AND does not break — i.e. the rule that settles the access question
// for those entries. A breaking rule is skipped: it grants what it grants and
// lets evaluation continue, so it never takes the decision away.
func firstDecider(rules []indexedRule, sel selector) string {
	for _, r := range rules {
		if hasBreak(r.body) {
			continue
		}
		if covers(ruleSelector(r.body), sel) {
			return r.body
		}
	}
	return ""
}

// indexed rebuilds olcAccess values from ordered bodies, as the server would
// renumber them.
func indexed(bodies []string) []string {
	out := make([]string, len(bodies))
	for i, b := range bodies {
		out[i] = fmt.Sprintf("{%d}%s", i, b)
	}
	return out
}

// findingKey identifies a finding across the before/after lists.
func findingKey(f Finding) string { return f.Level + "\x00" + f.Rule }

// InspectMove reports what moving rule `from` to position `to` would change
// beyond the order, and returns the resulting rule bodies (unindexed, in order)
// ready for a single olcAccess replace.
//
// The analysis is deliberately conservative: it reasons about full coverage
// (`covers`), so it reports what it can prove and stays quiet on rules that only
// partially overlap — it is a guard against the known trap, not a simulator of
// slapd.
func InspectMove(values []string, from, to int) (bodies []string, impact MoveImpact, err error) {
	bodies, err = Reorder(values, from, to)
	if err != nil {
		return nil, MoveImpact{}, err
	}
	before := splitRules(values)
	afterValues := indexed(bodies)
	after := splitRules(afterValues)

	if to < 0 || to >= len(bodies) {
		return bodies, MoveImpact{}, nil
	}
	impact.Moved = bodies[to]
	sel := ruleSelector(impact.Moved)

	// who used to decide for these entries, and who does now
	wasDecided := firstDecider(before, sel)
	nowDecided := firstDecider(after, sel)
	if wasDecided != "" && wasDecided != nowDecided {
		impact.Decided = wasDecided
		kept := map[string]bool{}
		for _, c := range byClauses(nowDecided) {
			kept[strings.TrimSpace(c)] = true
		}
		for _, c := range byClauses(wasDecided) {
			c = strings.TrimSpace(c)
			// `by * none` losing its place is the point of the move, not a loss
			if kept[c] || strings.HasPrefix(c, "* ") {
				continue
			}
			impact.Lost = append(impact.Lost, "by "+c)
		}
	}

	// rules the move newly makes unreachable
	had := map[string]bool{}
	for _, f := range Lint(values) {
		had[findingKey(f)] = true
	}
	for _, f := range Lint(afterValues) {
		if f.Level == LevelDead && !had[findingKey(f)] {
			impact.Dead = append(impact.Dead, f)
		}
	}
	return bodies, impact, nil
}

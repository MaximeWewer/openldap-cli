package acl

import (
	"fmt"
	"strings"
)

// Editing the ORDER or the MEMBERSHIP of olcAccess is not cosmetic: slapd stops
// at the first rule whose `to` matches, so moving or deleting a rule changes
// WHICH rule decides for the entries it covers. Raising a rule that ends in
// `by * none` above a broader one takes the broader rule's grantees off those
// entries; deleting the rule that answered for them hands the question to
// whatever sits below. Both happen silently, and `Lint` cannot see either
// (nothing became unreachable; the other rules still decide everywhere else).
// Impact is that missing check, shared by both edits.

// Impact is what an olcAccess edit would silently change.
type Impact struct {
	Rule string // the rule being moved or deleted
	// Lost are the `by` clauses that stop applying to Rule's entries, because
	// the rule that used to decide for them no longer gets the chance.
	Lost []string
	// Decided is the rule that decided for Rule's entries BEFORE the edit.
	Decided string
	// Now is the rule that decides for them AFTER it — empty when no rule
	// covers them any more, i.e. access there falls back to denied.
	Now string
	// Dead are the rules the edit newly makes unreachable.
	Dead []Finding
}

// Empty reports whether the edit changes nothing but the list itself.
func (m Impact) Empty() bool { return len(m.Lost) == 0 && len(m.Dead) == 0 }

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

// inspect compares the before/after rule lists and reports what changes for the
// entries `rule` covers.
//
// The analysis is deliberately conservative: it reasons about full coverage
// (`covers`), so it reports what it can prove and stays quiet on rules that only
// partially overlap — it is a guard against the known traps, not a simulator of
// slapd.
func inspect(beforeValues, afterValues []string, rule string) Impact {
	impact := Impact{Rule: rule}
	sel := ruleSelector(rule)

	// who used to decide for these entries, and who does now
	wasDecided := firstDecider(splitRules(beforeValues), sel)
	nowDecided := firstDecider(splitRules(afterValues), sel)
	if wasDecided != "" && wasDecided != nowDecided {
		impact.Decided, impact.Now = wasDecided, nowDecided
		kept := map[string]bool{}
		for _, c := range byClauses(nowDecided) {
			kept[strings.TrimSpace(c)] = true
		}
		for _, c := range byClauses(wasDecided) {
			c = strings.TrimSpace(c)
			// `by * none` losing its place is the point of the edit, not a loss
			if kept[c] || strings.HasPrefix(c, "* ") {
				continue
			}
			impact.Lost = append(impact.Lost, "by "+c)
		}
	}

	// rules the edit newly makes unreachable (ones already dead are not its doing)
	had := map[string]bool{}
	for _, f := range Lint(beforeValues) {
		had[findingKey(f)] = true
	}
	for _, f := range Lint(afterValues) {
		if f.Level == LevelDead && !had[findingKey(f)] {
			impact.Dead = append(impact.Dead, f)
		}
	}
	return impact
}

// InspectMove reports what moving rule `from` to position `to` would change
// beyond the order, and returns the resulting rule bodies (unindexed, in order)
// ready for a single olcAccess replace.
func InspectMove(values []string, from, to int) (bodies []string, impact Impact, err error) {
	bodies, err = Reorder(values, from, to)
	if err != nil {
		return nil, Impact{}, err
	}
	if to < 0 || to >= len(bodies) {
		return bodies, Impact{}, nil
	}
	return bodies, inspect(values, indexed(bodies), bodies[to]), nil
}

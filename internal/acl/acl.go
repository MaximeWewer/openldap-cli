// Package acl performs pure transformations on OpenLDAP olcAccess values.
//
// olcAccess is an ordered multi-valued attribute; each value is prefixed with
// an index like "{2}". Editing a value means deleting the old indexed string
// and adding the new one (same index). These functions compute those edits;
// the caller performs the LDAP read/modify.
package acl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Edit is one olcAccess change: delete Delete (empty = none) and add Add.
type Edit struct {
	Delete string
	Add    string
}

// indexedRule is one olcAccess value split into its {N} index and its body.
type indexedRule struct {
	idx  int
	body string
}

// splitRules parses the olcAccess values and orders them by their {N} index —
// the order slapd evaluates them in, and the order a whole-attribute replace
// must preserve. The server's response order is not guaranteed to match.
func splitRules(values []string) []indexedRule {
	rules := make([]indexedRule, 0, len(values))
	for _, v := range values {
		idx, body := SplitIndexed(v)
		rules = append(rules, indexedRule{idx, strings.TrimSpace(body)})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].idx < rules[j].idx })
	return rules
}

// SplitIndexed splits "{2}to ..." into (2, "to ..."). Returns (-1, v) if none.
func SplitIndexed(v string) (int, string) {
	if strings.HasPrefix(v, "{") {
		if i := strings.IndexByte(v, '}'); i > 0 {
			if n, err := strconv.Atoi(v[1:i]); err == nil {
				return n, v[i+1:]
			}
		}
	}
	return -1, v
}

// Reorder takes the indexed olcAccess values, sorts them by current index, moves
// the rule at position `from` to position `to`, and returns the rule bodies in
// the new order WITHOUT index prefixes — suitable for a single olcAccess replace
// (the server renumbers them {0},{1},… in this order). Positions are zero-based.
func Reorder(values []string, from, to int) ([]string, error) {
	type rule struct {
		idx  int
		body string
	}
	rules := make([]rule, len(values))
	for i, v := range values {
		idx, body := SplitIndexed(v)
		rules[i] = rule{idx, strings.TrimSpace(body)}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].idx < rules[j].idx })

	n := len(rules)
	if n == 0 {
		return nil, fmt.Errorf("no olcAccess rules to reorder")
	}
	if from < 0 || from >= n || to < 0 || to >= n {
		return nil, fmt.Errorf("index out of range: from=%d to=%d (have %d rules, {0}..{%d})", from, to, n, n-1)
	}

	bodies := make([]string, n)
	for i, r := range rules {
		bodies[i] = r.body
	}
	if from == to {
		return bodies, nil
	}
	moved := bodies[from]
	bodies = append(bodies[:from], bodies[from+1:]...) // remove
	bodies = append(bodies[:to], append([]string{moved}, bodies[to:]...)...)
	return bodies, nil
}

// DNWho builds the olcAccess "who" token for a single entry (dn.exact).
func DNWho(dn string) string { return fmt.Sprintf(`dn.exact="%s"`, dn) }

// GroupWho builds the olcAccess "who" token for a group's members (group.exact).
// Every member of the group then shares the granted access — the scalable way
// to give several service accounts the same rights on a tree.
func GroupWho(groupDN string) string { return fmt.Sprintf(`group.exact="%s"`, groupDN) }

// InjectOpts describes one olcAccess grant to inject.
type InjectOpts struct {
	Target string // the DN the rule protects
	Scope  string // "subtree" (default) or "base" (the container entry only)
	Filter string // optional LDAP filter — only entries matching it are covered
	Who    string // who-token: DNWho(dn) / GroupWho(dn)
	Access string // read, write, search, …

	// Terminator is the trailing `by *` action of a NEW rule: "break" (default,
	// additive — other identities fall through to the rules below) or "none".
	Terminator string
	// At is the index a NEW rule is inserted at; negative appends at the end.
	// Placing it above a broader rule is what stops it being shadowed.
	At int
}

// selector builds the rule's `to …` part.
func (o InjectOpts) selector() string {
	scope := o.Scope
	if scope == "" {
		scope = "subtree"
	}
	s := fmt.Sprintf("to dn.%s=%q", scope, o.Target)
	if o.Filter != "" {
		s += " filter=" + o.Filter
	}
	return s
}

// Inject adds `by <who> <access>` to the rule whose selector matches exactly
// (before its trailing `by *` clause), or returns a new rule when none matches.
// Adding a `by` clause to the SAME rule — rather than a second rule with the
// same `to`, which would be dead — is what lets multiple grantees coexist.
// sameSelector reports whether two `to …` parts select the same thing.
//
// Comparison is on the PARSED selector, not the text: slapd reads `dn.sub=` and
// `dn.subtree=` (and `dn.exact=`/`dn.base=`, and a bare `dn=`) as the same
// target, so matching on spelling would miss the existing rule and add a second
// one for the same target — which slapd then never reaches, the first having
// already decided.
//
// Every dimension must match, not just the DN: a rule narrowed by a different
// filter or attribute list is a DIFFERENT rule, and injecting a grant into it
// would hand out access on entries the caller never named. Selectors we cannot
// parse ("other") never match, so an unknown form gets its own rule rather than
// a clause in something we misread.
func sameSelector(a, b selector) bool {
	if a.kind == "other" || b.kind == "other" {
		return false
	}
	return a.kind == b.kind && a.scope == b.scope && a.dn == b.dn &&
		a.filter == b.filter && a.attrs == b.attrs
}

// matchesSelector reports whether a rule body selects exactly what o names.
func matchesSelector(body string, o InjectOpts) bool {
	return sameSelector(ruleSelector(body), parseSelector(o.selector()))
}

// RuleIndex returns the {N} index of the rule whose selector is exactly o's, or
// -1 when no rule protects that target. Callers use it to tell where a grant
// actually landed, which decides whether it is reachable.
func RuleIndex(values []string, o InjectOpts) int {
	for _, v := range values {
		idx, body := SplitIndexed(v)
		if matchesSelector(strings.TrimSpace(body), o) {
			return idx
		}
	}
	return -1
}

func Inject(values []string, o InjectOpts) (edit Edit, appended bool) {
	sel := o.selector()
	clause := fmt.Sprintf("by %s %s", o.Who, o.Access)

	for _, v := range values {
		idx, body := SplitIndexed(v)
		body = strings.TrimSpace(body)
		if !matchesSelector(body, o) {
			continue
		}
		// already granted -> no change (keeps re-runs idempotent)
		for _, c := range byClauses(body) {
			if strings.TrimSpace(c) == o.Who+" "+o.Access {
				return Edit{}, false
			}
		}
		var nb string
		switch {
		case strings.Contains(body, "by * none"):
			nb = strings.Replace(body, "by * none", clause+" by * none", 1)
		case strings.Contains(body, "by * break"):
			nb = strings.Replace(body, "by * break", clause+" by * break", 1)
		default:
			nb = strings.TrimRight(body, " ") + " " + clause
		}
		return Edit{Delete: v, Add: fmt.Sprintf("{%d}%s", idx, nb)}, false
	}

	term := o.Terminator
	if term == "" {
		term = "break"
	}
	rule := fmt.Sprintf("%s %s by * %s", sel, clause, term)
	if o.At >= 0 {
		rule = fmt.Sprintf("{%d}%s", o.At, rule)
	}
	return Edit{Add: rule}, true
}

// RemoveGrantee strips every `by <who> <access>` clause referencing who and
// drops the rules that are left doing nothing. `who` is a full who-token
// (DNWho/GroupWho).
//
// It returns the COMPLETE rule list in order, without index prefixes, for a
// single olcAccess replace (the server renumbers {0},{1},… from it) — the same
// mechanism as Reorder. A per-rule delete/add pair cannot work here: dropping a
// rule shifts the index of every rule below it, so the adds would land on the
// wrong ones.
//
// A rule is dropped when removing who leaves it with no `by` clause at all —
// slapd rejects such a rule outright ("no by clause(s) specified in access
// line"), which would make the whole revoke fail — or when every remaining
// clause is `by * break`, i.e. it neither grants nor denies and only costs a
// lookup. `by * none` is kept: that is a deliberate deny, and silently dropping
// it would widen access.
func RemoveGrantee(values []string, who string) (bodies []string, removed, dropped int) {
	return removeGrantee(values, who, nil)
}

// RemoveGranteeOn is RemoveGrantee restricted to the rules protecting target
// (any scope, filtered or not) — the counterpart of granting one tree. The
// account keeps whatever it was granted elsewhere.
func RemoveGranteeOn(values []string, who, target string) (bodies []string, removed, dropped int) {
	want := strings.ToLower(strings.TrimSpace(target))
	return removeGrantee(values, who, func(s selector) bool {
		return s.kind == "dn" && s.dn == want
	})
}

// removeGrantee strips who's clauses from the rules match accepts (nil = all).
func removeGrantee(values []string, who string, match func(selector) bool) (bodies []string, removed, dropped int) {
	for _, r := range splitRules(values) {
		if !strings.Contains(r.body, who) {
			bodies = append(bodies, r.body)
			continue
		}
		if match != nil {
			sel := r.body
			if i := strings.Index(r.body, " by "); i >= 0 {
				sel = r.body[:i]
			}
			if !match(parseSelector(sel)) {
				bodies = append(bodies, r.body)
				continue
			}
		}
		parts := strings.Split(r.body, " by ") // parts[0]="to <target>", rest="<who> <access>"
		kept := []string{parts[0]}
		for _, p := range parts[1:] {
			if strings.Contains(p, who) {
				removed++
				continue
			}
			kept = append(kept, p)
		}
		nb := strings.Join(kept, " by ")
		if len(kept) == 1 || isNoOp(nb) {
			dropped++
			continue
		}
		bodies = append(bodies, nb)
	}
	return bodies, removed, dropped
}
